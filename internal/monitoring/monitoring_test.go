// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package monitoring

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func mkCRD(name string) *unstructured.Unstructured {
	o := &unstructured.Unstructured{}
	o.SetAPIVersion("apiextensions.k8s.io/v1")
	o.SetKind("CustomResourceDefinition")
	o.SetName(name)
	return o
}

func mkNonCRD() *unstructured.Unstructured {
	o := &unstructured.Unstructured{}
	o.SetAPIVersion("v1")
	o.SetKind("ConfigMap")
	o.SetName("noise")
	return o
}

func TestFilterCRDs_PicksWantedInOrderAndDropsRest(t *testing.T) {
	objs := []*unstructured.Unstructured{
		mkCRD("podmonitors.monitoring.coreos.com"),
		mkCRD("alertmanagers.monitoring.coreos.com"),
		mkCRD("servicemonitors.monitoring.coreos.com"),
		mkNonCRD(),
	}
	got := filterCRDs(objs, []string{
		"servicemonitors.monitoring.coreos.com",
		"podmonitors.monitoring.coreos.com",
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 CRDs, got %d", len(got))
	}
	if got[0].GetName() != "servicemonitors.monitoring.coreos.com" {
		t.Errorf("filter must preserve requested order; got %s first", got[0].GetName())
	}
	if got[1].GetName() != "podmonitors.monitoring.coreos.com" {
		t.Errorf("got %s second", got[1].GetName())
	}
}

func TestFilterCRDs_MissingCRDReturnsShortList(t *testing.T) {
	objs := []*unstructured.Unstructured{
		mkCRD("servicemonitors.monitoring.coreos.com"),
	}
	got := filterCRDs(objs, []string{
		"servicemonitors.monitoring.coreos.com",
		"podmonitors.monitoring.coreos.com",
	})
	if len(got) != 1 {
		t.Fatalf("missing CRD should produce a short list, got %d entries", len(got))
	}
}
