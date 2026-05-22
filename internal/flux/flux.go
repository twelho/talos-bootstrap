// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package flux installs the Flux GitOps controllers. Repository sources and
// sync objects are intentionally left to post-bootstrap manifests, matching how
// OCI-packaged and other non-Git configurations are already applied.
package flux

import (
	"context"
	"fmt"
	"strings"

	"github.com/fluxcd/flux2/v2/pkg/manifestgen/install"

	"github.com/twelho/talos-bootstrap/internal/config"
	"github.com/twelho/talos-bootstrap/internal/kube"
	"github.com/twelho/talos-bootstrap/internal/manifests"
)

// Apply installs Flux into the cluster via generated manifests.
func Apply(ctx context.Context, c *kube.Client, cfg *config.Flux) error {
	opts := install.MakeDefaultOptions()
	opts.Namespace = "flux-system"
	if c := splitCSV(cfg.Components); len(c) > 0 {
		opts.Components = c
	}
	if c := splitCSV(cfg.ComponentsExtra); len(c) > 0 {
		opts.ComponentsExtra = c
	}
	opts.WatchAllNamespaces = cfg.AllNamespacesEnabled()
	opts.NetworkPolicy = cfg.NetworkPolicyEnabled()

	tmp, err := install.Generate(opts, "")
	if err != nil {
		return fmt.Errorf("generate flux manifests: %w", err)
	}
	objs, err := manifests.DecodeStream([]byte(tmp.Content))
	if err != nil {
		return fmt.Errorf("decode flux manifests: %w", err)
	}
	if err := manifests.Apply(ctx, c, objs); err != nil {
		return fmt.Errorf("apply flux manifests: %w", err)
	}
	return nil
}

// splitCSV splits on commas and discards empty entries so a stray comma
// ("source-controller,,kustomize-controller") does not become a component
// name that Flux will reject.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
