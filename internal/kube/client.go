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

	"github.com/rs/zerolog/log"
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

// Client is the single client-go entry point used by this project. The
// discovery cache and REST mapper are constructed once so they can be shared
// across server-side apply and cleanup calls.
type Client struct {
	config    *rest.Config
	clientset *kubernetes.Clientset
	dynamic   dynamic.Interface
	discovery discovery.DiscoveryInterface
	mapper    *restmapper.DeferredDiscoveryRESTMapper
}

// NewFromKubeconfig builds a Client from a kubeconfig file. An empty path
// resolves via DefaultKubeconfigPath: the KUBECONFIG env var if set, else
// ~/.kube/config. The full clientcmd loading-rules precedence (merged
// kubeconfig fragments, command-line overrides) is not honoured.
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
		config:    cfg,
		clientset: cs,
		dynamic:   dyn,
		discovery: disc,
		mapper:    mapper,
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
// expires. Used to bridge a control-plane reboot window.
func WaitAPIServer(ctx context.Context, host string, port int) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: 2 * time.Second}
	for {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		log.Debug().Err(err).Str("addr", addr).Msg("kube api unreachable, retrying")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// EnsureNamespace creates a namespace if it does not already exist.
func (c *Client) EnsureNamespace(ctx context.Context, name string) error {
	_, err := c.clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}, metav1.CreateOptions{FieldManager: FieldManager})
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return fmt.Errorf("create namespace %q: %w", name, err)
}

// EnsureSecret creates an opaque secret with the given key/value data. If a
// secret of the same name already exists it is left untouched: SOPS keys are
// written once and never rotated by this tool.
func (c *Client) EnsureSecret(ctx context.Context, namespace, name string, data map[string][]byte) error {
	if err := c.EnsureNamespace(ctx, namespace); err != nil {
		return err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       data,
	}
	_, err := c.clientset.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{FieldManager: FieldManager})
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
		ri = c.dynamic.Resource(gv).Namespace(namespace)
	} else {
		ri = c.dynamic.Resource(gv)
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

var (
	deploymentGVR = GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	daemonSetGVR  = GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}
)

// RolloutRestartDeployment bumps the restartedAt annotation on a Deployment's
// pod template, mirroring `kubectl rollout restart deployment`.
func (c *Client) RolloutRestartDeployment(ctx context.Context, namespace, name string) error {
	return c.rolloutRestart(ctx, deploymentGVR, namespace, name)
}

// RolloutRestartDaemonSet is the DaemonSet counterpart to RolloutRestartDeployment.
func (c *Client) RolloutRestartDaemonSet(ctx context.Context, namespace, name string) error {
	return c.rolloutRestart(ctx, daemonSetGVR, namespace, name)
}

func (c *Client) rolloutRestart(ctx context.Context, gvr GroupVersionResource, namespace, name string) error {
	patch := fmt.Sprintf(
		`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
		time.Now().Format(time.RFC3339),
	)
	_, err := c.dynamic.Resource(gvr.toUnstructuredGVR()).Namespace(namespace).
		Patch(ctx, name, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{FieldManager: FieldManager})
	if err != nil {
		return fmt.Errorf("rollout restart %s/%s/%s: %w", gvr.Resource, namespace, name, err)
	}
	return nil
}
