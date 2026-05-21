// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package manifests turns a Kustomize directory into typed unstructured
// resources, partitions CRDs from everything else, and applies them to a
// cluster in the right order. It replaces the regex-based YAML splitting from
// the Python original with a real YAML stream parser.
package manifests

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
	"sigs.k8s.io/yaml"
	yamlv3 "gopkg.in/yaml.v3"

	"github.com/twelho/talos-bootstrap/internal/kube"
)

const (
	crdAPIVersion = "apiextensions.k8s.io/v1"
	crdKind       = "CustomResourceDefinition"
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

// Partition separates CustomResourceDefinitions from the rest. CRDs must be
// applied before resources that reference them.
func Partition(objs []*unstructured.Unstructured) (crds, rest []*unstructured.Unstructured) {
	for _, o := range objs {
		if isCRD(o) {
			crds = append(crds, o)
		} else {
			rest = append(rest, o)
		}
	}
	return crds, rest
}

func isCRD(o *unstructured.Unstructured) bool {
	return o.GetAPIVersion() == crdAPIVersion && o.GetKind() == crdKind
}

// Apply server-side applies CRDs first, then everything else. This matches
// the Python original and avoids reconciliation order races on first install.
func Apply(ctx context.Context, c *kube.Client, objs []*unstructured.Unstructured) error {
	crds, rest := Partition(objs)
	if err := c.ApplyServerSide(ctx, crds); err != nil {
		return fmt.Errorf("apply CRDs: %w", err)
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
	dec := yamlv3.NewDecoder(bytes.NewReader(data))
	var out []*unstructured.Unstructured
	for {
		var raw any
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("yaml decode: %w", err)
		}
		if raw == nil {
			continue
		}
		// Re-marshal as JSON via sigs.k8s.io/yaml so that integer/string
		// distinctions match what client-go expects, then unmarshal to
		// Unstructured.
		j, err := yaml.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("yaml re-encode: %w", err)
		}
		obj := &unstructured.Unstructured{}
		if err := yaml.Unmarshal(j, &obj.Object); err != nil {
			return nil, fmt.Errorf("decode unstructured: %w", err)
		}
		if len(obj.Object) == 0 {
			continue
		}
		out = append(out, obj)
	}
	return out, nil
}
