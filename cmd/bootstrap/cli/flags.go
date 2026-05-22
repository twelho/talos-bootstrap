// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package cli

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// nodeOverrides is a pflag.Value that accumulates `--bootstrap` entries of the
// form "node" (bootstrap, address by FQDN) or "node=endpoint" (bootstrap, use
// this endpoint to reach the un-configured node). The flag may be repeated and
// each occurrence may carry comma-separated entries. Repetition is preferred
// for endpoints containing commas (IPv6 literals).
type nodeOverrides struct {
	Nodes map[string]string
}

func (n *nodeOverrides) Set(raw string) error {
	if n.Nodes == nil {
		n.Nodes = map[string]string{}
	}
	for entry := range strings.SplitSeq(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		node, endpoint, _ := strings.Cut(entry, "=")
		node = strings.TrimSpace(node)
		endpoint = strings.TrimSpace(endpoint)
		if node == "" {
			return fmt.Errorf("empty node name in %q", entry)
		}
		n.Nodes[node] = endpoint
	}
	return nil
}

func (n *nodeOverrides) String() string {
	if len(n.Nodes) == 0 {
		return ""
	}
	parts := make([]string, 0, len(n.Nodes))
	for _, k := range slices.Sorted(maps.Keys(n.Nodes)) {
		if v := n.Nodes[k]; v != "" {
			parts = append(parts, k+"="+v)
			continue
		}
		parts = append(parts, k)
	}
	return strings.Join(parts, ",")
}

func (n *nodeOverrides) Type() string { return "node[=endpoint]" }
