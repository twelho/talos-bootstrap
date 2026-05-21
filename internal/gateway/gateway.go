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
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/twelho/talos-bootstrap/internal/kube"
	"github.com/twelho/talos-bootstrap/internal/manifests"
)

const (
	ciliumGoMod    = "https://raw.githubusercontent.com/cilium/cilium/v%s/go.mod"
	releasesAPI    = "https://api.github.com/repos/kubernetes-sigs/gateway-api/releases"
	bundleTemplate = "https://github.com/kubernetes-sigs/gateway-api/releases/download/%s/experimental-install.yaml"
)

var (
	gatewayAPIPin    = regexp.MustCompile(`sigs\.k8s\.io/gateway-api\s+(v[\d.]+)`)
	majorMinorPrefix = regexp.MustCompile(`^v\d+\.\d+`)
)

// ResolveVersion finds the highest non-rc Gateway API release tag that shares
// the major.minor prefix with the version Cilium pins in go.mod.
func ResolveVersion(ctx context.Context, ciliumVersion string) (string, error) {
	mod, err := httpGet(ctx, fmt.Sprintf(ciliumGoMod, ciliumVersion))
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

	releases, err := httpGet(ctx, releasesAPI)
	if err != nil {
		return "", fmt.Errorf("list gateway-api releases: %w", err)
	}
	var entries []struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(releases, &entries); err != nil {
		return "", fmt.Errorf("parse gateway-api releases: %w", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.TagName, prefix) && !strings.Contains(e.TagName, "rc") {
			return e.TagName, nil
		}
	}
	return "", fmt.Errorf("no stable gateway-api release for %s", prefix)
}

// InstallCRDs fetches the experimental-install bundle for the given Gateway
// API release and server-side applies it.
func InstallCRDs(ctx context.Context, c *kube.Client, version string) error {
	body, err := httpGet(ctx, fmt.Sprintf(bundleTemplate, version))
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

func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	cli := &http.Client{Timeout: 30 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}
