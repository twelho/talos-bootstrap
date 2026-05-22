// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package config

import "testing"

func TestClusterFQDN(t *testing.T) {
	cases := []struct {
		name   string
		domain string
		parts  []string
		want   string
	}{
		{"bare with domain", "example.com", []string{"worker"}, "worker.example.com"},
		{"bare two-part with domain", "example.com", []string{"api", "cluster"}, "api.cluster.example.com"},
		{"already FQDN under domain", "example.com", []string{"worker.example.com"}, "worker.example.com"},
		{"part equals domain", "example.com", []string{"example.com"}, "example.com"},
		{"ipv4 literal ignores domain", "example.com", []string{"10.0.0.1"}, "10.0.0.1"},
		{"ipv6 literal ignores domain", "example.com", []string{"fd00::1"}, "fd00::1"},
		{"no domain returns join", "", []string{"worker", "local"}, "worker.local"},
		{"empty parts with domain returns domain", "example.com", []string{""}, "example.com"},
		{"empty parts no domain returns empty", "", nil, ""},
		{"unrelated domain still appended", "example.com", []string{"worker.other.com"}, "worker.other.com.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Cluster{Domain: tc.domain}
			if got := c.FQDN(tc.parts...); got != tc.want {
				t.Errorf("FQDN(%v) with domain=%q: got %q, want %q", tc.parts, tc.domain, got, tc.want)
			}
		})
	}
}
