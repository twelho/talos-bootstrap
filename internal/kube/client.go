// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package kube wraps client-go for the small set of cluster-side operations
// the bootstrap flow needs: server-side apply of arbitrary YAML, idempotent
// namespace and secret creation, label-selector cleanup of the default CNI
// resources, kubeconfig writing, and rollout restarts.
package kube

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	memorycache "k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

const FieldManager = "talos-bootstrap"

// Client bundles the few client-go interfaces this project uses. Holding them
// together avoids re-deriving the discovery and REST mapper on every call.
type Client struct {
	Config    *rest.Config
	Clientset *kubernetes.Clientset
	Dynamic   dynamic.Interface
	Discovery discovery.DiscoveryInterface
	Mapper    *restmapper.DeferredDiscoveryRESTMapper
}

// NewFromKubeconfig builds a Client from a kubeconfig file. Empty path means
// the standard precedence (KUBECONFIG env, then ~/.kube/config).
func NewFromKubeconfig(path string) (*Client, error) {
	if path == "" {
		path = DefaultKubeconfigPath()
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig %q: %w", path, err)
	}
	return newFromConfig(cfg)
}

func newFromConfig(cfg *rest.Config) (*Client, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes clientset: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("dynamic client: %w", err)
	}
	disc := cs.Discovery()
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memorycache.NewMemCacheClient(disc))
	return &Client{
		Config:    cfg,
		Clientset: cs,
		Dynamic:   dyn,
		Discovery: disc,
		Mapper:    mapper,
	}, nil
}

// WriteKubeconfig writes raw kubeconfig bytes to the standard kubeconfig path
// (overwriting any existing file) with mode 0600. Empty path resolves like
// DefaultKubeconfigPath.
func WriteKubeconfig(path string, data []byte) error {
	if path == "" {
		path = DefaultKubeconfigPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create kubeconfig dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write kubeconfig: %w", err)
	}
	return nil
}

// DefaultKubeconfigPath honours the KUBECONFIG env var and falls back to the
// standard ~/.kube/config location, both of which clientcmd already exposes
// as named constants.
func DefaultKubeconfigPath() string {
	if p := os.Getenv(clientcmd.RecommendedConfigPathEnvVar); p != "" {
		return p
	}
	return clientcmd.RecommendedHomeFile
}

// WaitAPIServer dials a TCP port until it accepts a connection or the context
// expires. Useful while a control-plane node is rebooting and the API server
// has not yet come back up.
func WaitAPIServer(ctx context.Context, host string, port int) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: 2 * time.Second}
	for {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// EnsureNamespace creates a namespace if it does not already exist.
func (c *Client) EnsureNamespace(ctx context.Context, name string) error {
	_, err := c.Clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}, metav1.CreateOptions{FieldManager: FieldManager})
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return fmt.Errorf("create namespace %q: %w", name, err)
}

// EnsureSecret creates an opaque secret with the given key/value data. If a
// secret of the same name already exists it is left untouched (the Python
// behaviour: SOPS keys are written once and never rotated by this tool).
func (c *Client) EnsureSecret(ctx context.Context, namespace, name string, data map[string][]byte) error {
	if err := c.EnsureNamespace(ctx, namespace); err != nil {
		return err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       data,
	}
	_, err := c.Clientset.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{FieldManager: FieldManager})
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return fmt.Errorf("create secret %s/%s: %w", namespace, name, err)
}

// ResourceExists returns true if a single named resource of the given GVR
// exists. Namespace may be empty for cluster-scoped resources.
func (c *Client) ResourceExists(ctx context.Context, gvr GroupVersionResource, namespace, name string) (bool, error) {
	gv := gvr.toUnstructuredGVR()
	var ri dynamic.ResourceInterface
	if namespace != "" {
		ri = c.Dynamic.Resource(gv).Namespace(namespace)
	} else {
		ri = c.Dynamic.Resource(gv)
	}
	_, err := ri.Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return false, err
}

// CRDExists is a typed convenience for the most common ResourceExists call.
func (c *Client) CRDExists(ctx context.Context, name string) (bool, error) {
	return c.ResourceExists(ctx, GroupVersionResource{
		Group:    "apiextensions.k8s.io",
		Version:  "v1",
		Resource: "customresourcedefinitions",
	}, "", name)
}

// RolloutRestart bumps the kubectl.kubernetes.io/restartedAt annotation on a
// workload, mirroring `kubectl rollout restart`. The kind is one of
// "deployment" or "daemonset"; other kinds are not exercised by this project.
func (c *Client) RolloutRestart(ctx context.Context, kind, namespace, name string) error {
	gvr, err := rolloutGVR(kind)
	if err != nil {
		return err
	}
	patch := fmt.Sprintf(
		`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
		time.Now().Format(time.RFC3339),
	)
	_, err = c.Dynamic.Resource(gvr.toUnstructuredGVR()).Namespace(namespace).
		Patch(ctx, name, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{FieldManager: FieldManager})
	if err != nil {
		return fmt.Errorf("rollout restart %s/%s/%s: %w", kind, namespace, name, err)
	}
	return nil
}

func rolloutGVR(kind string) (GroupVersionResource, error) {
	switch kind {
	case "deployment":
		return GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, nil
	case "daemonset":
		return GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}, nil
	default:
		return GroupVersionResource{}, fmt.Errorf("rollout restart: unsupported kind %q", kind)
	}
}

