// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package monitoring installs the subset of prometheus-operator CRDs that
// Cilium's chart-side validate.yaml requires when ServiceMonitor / PodMonitor
// emission is enabled. Without these CRDs present at chart render time, the
// Cilium install fails and downstream consumers had to fork the rendered
// values with `serviceMonitor.trustCRDsExist: true`.
//
// This package owns only the two CRDs Cilium needs (ServiceMonitor,
// PodMonitor). The downstream monitoring stack (kube-prometheus-stack or
// equivalent) installs the full operator and may co-own these CRD objects.
// Server-side apply with talos-bootstrap as the field manager is compatible
// with that handoff; see INTEGRATION.md.
package monitoring

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/twelho/talos-bootstrap/internal/githttp"
	"github.com/twelho/talos-bootstrap/internal/kube"
	"github.com/twelho/talos-bootstrap/internal/manifests"
)

// Version pins the prometheus-operator release whose stripped CRD bundle we
// install. Bump as the Cilium chart's expectations advance; the
// stripped-down-crds.yaml asset path has been stable across releases.
const Version = "v0.86.0"

const bundleURL = "https://github.com/prometheus-operator/prometheus-operator/releases/download/%s/stripped-down-crds.yaml"

// CRDs lists the resources this package installs. Exported so callers can
// wait for them by name (see kube.Client.WaitCRDEstablished).
var CRDs = []string{
	"servicemonitors.monitoring.coreos.com",
	"podmonitors.monitoring.coreos.com",
}

// InstallCRDs downloads the stripped CRD bundle for the pinned
// prometheus-operator release, filters it to just the CRDs this package
// owns, and server-side applies them.
func InstallCRDs(ctx context.Context, c *kube.Client) error {
	body, err := githttp.Get(ctx, fmt.Sprintf(bundleURL, Version))
	if err != nil {
		return fmt.Errorf("download prometheus-operator %s CRDs: %w", Version, err)
	}
	objs, err := manifests.DecodeStream(body)
	if err != nil {
		return fmt.Errorf("decode prometheus-operator CRDs: %w", err)
	}
	wanted := filterCRDs(objs, CRDs)
	if len(wanted) != len(CRDs) {
		return fmt.Errorf("prometheus-operator %s bundle missing one of %v (got %d of %d)",
			Version, CRDs, len(wanted), len(CRDs))
	}
	if err := c.ApplyServerSide(ctx, wanted); err != nil {
		return fmt.Errorf("apply prometheus-operator CRDs: %w", err)
	}
	return nil
}

// filterCRDs returns the entries in objs whose name matches one of names, in
// the order given by names. Non-CRD objects are dropped.
func filterCRDs(objs []*unstructured.Unstructured, names []string) []*unstructured.Unstructured {
	byName := map[string]*unstructured.Unstructured{}
	for _, o := range objs {
		if o.GetAPIVersion() == "apiextensions.k8s.io/v1" && o.GetKind() == "CustomResourceDefinition" {
			byName[o.GetName()] = o
		}
	}
	out := make([]*unstructured.Unstructured, 0, len(names))
	for _, n := range names {
		if o, ok := byName[n]; ok {
			out = append(out, o)
		}
	}
	return out
}
