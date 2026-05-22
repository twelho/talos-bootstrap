// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package githttp wraps net/http for fetches against github.com and
// api.github.com. It transparently injects a bearer token from the user's
// GITHUB_TOKEN / GH_TOKEN env when one is available (avoids the 60-req/hr
// anonymous limit on shared NATs) and parses the Link header so callers can
// page through GitHub API list endpoints.
package githttp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var linkNextRel = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// Get performs a one-shot GET against the given URL. The pagination link
// header (if any) is discarded.
func Get(ctx context.Context, url string) ([]byte, error) {
	body, _, err := GetWithNext(ctx, url)
	return body, err
}

// GetWithNext performs a GET and returns both the body and the URL of the
// next page from a GitHub-style Link header. The next URL is "" when no
// pagination header is present.
func GetWithNext(ctx context.Context, url string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	if strings.HasPrefix(url, "https://api.github.com/") {
		if tok := githubToken(); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		}
	}
	cli := &http.Client{Timeout: 30 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	return body, NextPageURL(resp.Header.Get("Link")), nil
}

// NextPageURL extracts the rel="next" target from a GitHub-style Link header.
// Exported so tests can pin the pagination semantics without an HTTP round trip.
func NextPageURL(link string) string {
	if link == "" {
		return ""
	}
	m := linkNextRel.FindStringSubmatch(link)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func githubToken() string {
	for _, name := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}
