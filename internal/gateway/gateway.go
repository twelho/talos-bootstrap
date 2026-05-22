// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package gateway resolves the Gateway API CRD release that matches the
// installed Cilium version and applies it to the cluster. It uses the
// experimental-install bundle: Cilium's HTTPRoute reconciler currently fails
// when the TLSRoute CRD is absent (cilium/cilium#38874 only fixed this
// partially), so the experimental bundle is the safe choice until that lands
// upstream.
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/twelho/talos-bootstrap/internal/githttp"
	"github.com/twelho/talos-bootstrap/internal/kube"
	"github.com/twelho/talos-bootstrap/internal/manifests"
)

const (
	ciliumGoMod     = "https://raw.githubusercontent.com/cilium/cilium/v%s/go.mod"
	releasesAPI     = "https://api.github.com/repos/kubernetes-sigs/gateway-api/releases?per_page=100"
	bundleTemplate  = "https://github.com/kubernetes-sigs/gateway-api/releases/download/%s/experimental-install.yaml"
	maxReleasePages = 10
)

var (
	gatewayAPIPin    = regexp.MustCompile(`sigs\.k8s\.io/gateway-api\s+(v[\d.]+)`)
	majorMinorPrefix = regexp.MustCompile(`^v\d+\.\d+`)
)

// ResolveVersion finds the highest non-rc Gateway API release tag that shares
// the major.minor prefix with the version Cilium pins in go.mod. Pages through
// GitHub's release list until a match is found or maxReleasePages is reached.
func ResolveVersion(ctx context.Context, ciliumVersion string) (string, error) {
	mod, err := githttp.Get(ctx, fmt.Sprintf(ciliumGoMod, ciliumVersion))
	if err != nil {
		return "", fmt.Errorf("fetch cilium go.mod: %w", err)
	}
	pinned := gatewayAPIPin.FindStringSubmatch(string(mod))
	if len(pinned) < 2 {
		return "", fmt.Errorf("gateway-api pin not found in cilium go.mod")
	}
	prefix := majorMinorPrefix.FindString(pinned[1])
	if prefix == "" {
		return "", fmt.Errorf("invalid gateway-api version pin: %q", pinned[1])
	}

	url := releasesAPI
	for page := 0; page < maxReleasePages; page++ {
		body, next, err := githttp.GetWithNext(ctx, url)
		if err != nil {
			return "", fmt.Errorf("list gateway-api releases: %w", err)
		}
		var entries []struct {
			TagName string `json:"tag_name"`
		}
		if err := json.Unmarshal(body, &entries); err != nil {
			return "", fmt.Errorf("parse gateway-api releases: %w", err)
		}
		for _, e := range entries {
			// Releases come newest-first; the first stable tag matching the
			// major.minor prefix wins. Reject release candidates by their "-rc"
			// suffix marker so we don't match arbitrary substrings.
			if strings.HasPrefix(e.TagName, prefix) && !strings.Contains(e.TagName, "-rc") {
				return e.TagName, nil
			}
		}
		if next == "" {
			break
		}
		url = next
	}
	return "", fmt.Errorf("no stable gateway-api release for %s (scanned %d pages)", prefix, maxReleasePages)
}

// InstallCRDs fetches the experimental-install bundle for the given Gateway
// API release and server-side applies it.
func InstallCRDs(ctx context.Context, c *kube.Client, version string) error {
	body, err := githttp.Get(ctx, fmt.Sprintf(bundleTemplate, version))
	if err != nil {
		return fmt.Errorf("download gateway-api %s: %w", version, err)
	}
	objs, err := manifests.DecodeStream(body)
	if err != nil {
		return fmt.Errorf("decode gateway-api manifests: %w", err)
	}
	if err := c.ApplyServerSide(ctx, objs); err != nil {
		return fmt.Errorf("apply gateway-api manifests: %w", err)
	}
	return nil
}
