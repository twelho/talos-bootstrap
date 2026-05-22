// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package manifests

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func makeObj(apiVersion, kind, name string) *unstructured.Unstructured {
	o := &unstructured.Unstructured{}
	o.SetAPIVersion(apiVersion)
	o.SetKind(kind)
	o.SetName(name)
	return o
}

func TestPartition_SeparatesCRDsNamespacesAndRest(t *testing.T) {
	objs := []*unstructured.Unstructured{
		makeObj("apiextensions.k8s.io/v1", "CustomResourceDefinition", "things.example.com"),
		makeObj("v1", "ConfigMap", "cm"),
		makeObj("v1", "Namespace", "team-a"),
		makeObj("apiextensions.k8s.io/v1", "CustomResourceDefinition", "more.example.com"),
		makeObj("apps/v1", "Deployment", "d"),
	}
	crds, namespaces, rest := Partition(objs)
	if len(crds) != 2 {
		t.Fatalf("expected 2 CRDs, got %d", len(crds))
	}
	if len(namespaces) != 1 {
		t.Fatalf("expected 1 Namespace, got %d", len(namespaces))
	}
	if len(rest) != 2 {
		t.Fatalf("expected 2 other objects, got %d", len(rest))
	}
}

func TestPartition_EmptyInputProducesEmptyOutputs(t *testing.T) {
	crds, namespaces, rest := Partition(nil)
	if len(crds) != 0 || len(namespaces) != 0 || len(rest) != 0 {
		t.Errorf("empty input should yield empty partitions, got %d/%d/%d", len(crds), len(namespaces), len(rest))
	}
}

func TestDecodeStream_MultiDoc(t *testing.T) {
	data := []byte(`---
apiVersion: v1
kind: ConfigMap
metadata:
  name: a
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: b
---
`)
	objs, err := DecodeStream(data)
	if err != nil {
		t.Fatalf("DecodeStream: %v", err)
	}
	if len(objs) != 2 {
		t.Fatalf("expected 2 objects, got %d", len(objs))
	}
	if objs[0].GetName() != "a" || objs[1].GetName() != "b" {
		t.Errorf("unexpected object names: %s, %s", objs[0].GetName(), objs[1].GetName())
	}
}

func TestDecodeStream_PreservesIntStringDistinction(t *testing.T) {
	// Numeric-looking strings (name: "80") must remain strings and integers
	// (port: 80) must remain numeric so client-go's IntOrString conversions
	// dispatch correctly. The YAMLOrJSONDecoder yields JSON-compatible
	// scalars (float64 for numbers), which is fine: the typed conversion at
	// apply time handles the rest.
	data := []byte(`apiVersion: v1
kind: Service
metadata:
  name: s
spec:
  ports:
  - port: 80
    name: "80"
`)
	objs, err := DecodeStream(data)
	if err != nil {
		t.Fatalf("DecodeStream: %v", err)
	}
	if len(objs) != 1 {
		t.Fatalf("expected 1 object, got %d", len(objs))
	}
	ports, ok, err := unstructured.NestedSlice(objs[0].Object, "spec", "ports")
	if err != nil || !ok {
		t.Fatalf("spec.ports missing: ok=%v err=%v", ok, err)
	}
	p := ports[0].(map[string]any)
	switch p["port"].(type) {
	case int64, float64, int:
	default:
		t.Errorf("port should decode as numeric, got %T (%v)", p["port"], p["port"])
	}
	if _, isStr := p["name"].(string); !isStr {
		t.Errorf("name should decode as string, got %T (%v)", p["name"], p["name"])
	}
}
