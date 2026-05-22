// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package manifests turns a Kustomize directory into typed unstructured
// resources, partitions CRDs from everything else, and applies them to a
// cluster in the right order. CRDs are applied first and waited on for the
// Established condition before the rest are applied, so a single bundle may
// safely mix a CRD with an instance of that CR.
package manifests

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"

	"github.com/twelho/talos-bootstrap/internal/kube"
)

const (
	crdAPIVersion       = "apiextensions.k8s.io/v1"
	crdKind             = "CustomResourceDefinition"
	namespaceAPIVersion = "v1"
	namespaceKind       = "Namespace"
)

// Render runs Kustomize on the given directory with helm enabled and root
// load restrictions removed (matching `kubectl kustomize --enable-helm
// --load-restrictor=LoadRestrictionsNone`).
func Render(dir string) ([]*unstructured.Unstructured, error) {
	opts := krusty.MakeDefaultOptions()
	opts.LoadRestrictions = types.LoadRestrictionsNone
	opts.PluginConfig = types.EnabledPluginConfig(types.BploUseStaticallyLinked)

	k := krusty.MakeKustomizer(opts)
	rm, err := k.Run(filesys.MakeFsOnDisk(), dir)
	if err != nil {
		return nil, fmt.Errorf("kustomize %q: %w", dir, err)
	}
	out, err := rm.AsYaml()
	if err != nil {
		return nil, fmt.Errorf("serialize kustomize output: %w", err)
	}
	return decodeStream(out)
}

// Partition splits objects into CRDs, Namespaces, and everything else. Apply
// orders them as CRDs -> Namespaces -> rest so that:
//   - a bundle may mix a CRD with an instance of that CR
//   - a bundle may mix a Namespace with resources that live in it (a 404 race
//     otherwise hits namespaced resources whose namespace is created in the
//     same apply pass)
func Partition(objs []*unstructured.Unstructured) (crds, namespaces, rest []*unstructured.Unstructured) {
	for _, o := range objs {
		switch {
		case isCRD(o):
			crds = append(crds, o)
		case isNamespace(o):
			namespaces = append(namespaces, o)
		default:
			rest = append(rest, o)
		}
	}
	return crds, namespaces, rest
}

func isCRD(o *unstructured.Unstructured) bool {
	return o.GetAPIVersion() == crdAPIVersion && o.GetKind() == crdKind
}

func isNamespace(o *unstructured.Unstructured) bool {
	return o.GetAPIVersion() == namespaceAPIVersion && o.GetKind() == namespaceKind
}

// Apply server-side applies CRDs first, waits for them to become Established,
// then applies Namespaces, then everything else. The ordering avoids the
// races where an instance of a freshly-applied CRD is rejected (its API
// endpoint is not yet served) or a namespaced resource is rejected because
// its Namespace has not yet committed.
func Apply(ctx context.Context, c *kube.Client, objs []*unstructured.Unstructured) error {
	crds, namespaces, rest := Partition(objs)
	if err := c.ApplyServerSide(ctx, crds); err != nil {
		return fmt.Errorf("apply CRDs: %w", err)
	}
	for _, crd := range crds {
		if err := c.WaitCRDEstablished(ctx, crd.GetName()); err != nil {
			return fmt.Errorf("wait CRD %s: %w", crd.GetName(), err)
		}
	}
	if err := c.ApplyServerSide(ctx, namespaces); err != nil {
		return fmt.Errorf("apply namespaces: %w", err)
	}
	if err := c.ApplyServerSide(ctx, rest); err != nil {
		return fmt.Errorf("apply manifests: %w", err)
	}
	return nil
}

// DecodeStream parses a YAML stream that may contain multiple documents.
// Empty documents are skipped. Exported so the gateway-api installer can
// reuse it for raw YAML fetched over HTTPS.
func DecodeStream(data []byte) ([]*unstructured.Unstructured, error) {
	return decodeStream(data)
}

func decodeStream(data []byte) ([]*unstructured.Unstructured, error) {
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var out []*unstructured.Unstructured
	for {
		obj := &unstructured.Unstructured{}
		if err := dec.Decode(&obj.Object); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("yaml decode: %w", err)
		}
		if len(obj.Object) == 0 {
			continue
		}
		out = append(out, obj)
	}
	return out, nil
}
