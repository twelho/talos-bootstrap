// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package facts derives the small, stable set of cluster facts downstream
// GitOps repos need to template against. The JSON contract is versioned via
// SchemaVersion: additive changes are allowed at the current version, any
// breaking key rename or removal must bump it.
//
// The output is intentionally safe to commit / publish: secrets paths, GPG
// fingerprints, and any other local-filesystem or sensitive value are omitted.
package facts

import (
	"maps"
	"net"
	"slices"
	"strconv"

	"github.com/twelho/talos-bootstrap/internal/config"
)

// SchemaVersion is the contract version of the JSON document. Downstream
// consumers should refuse to parse a document whose schemaVersion they do not
// recognize.
const SchemaVersion = 1

const apiServerPort = 6443

type Facts struct {
	SchemaVersion int          `json:"schemaVersion"`
	Cluster       Cluster      `json:"cluster"`
	Network       Network      `json:"network"`
	ControlPlane  ControlPlane `json:"controlPlane"`
	Worker        Worker       `json:"worker"`
	Features      Features     `json:"features"`
}

type Cluster struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	FQDN   string `json:"fqdn"`
}

type Network struct {
	IPv4NativeRoutingCIDR string `json:"ipv4NativeRoutingCIDR"`
}

type ControlPlane struct {
	Record   string   `json:"record"`
	Endpoint string   `json:"endpoint"`
	Nodes    []string `json:"nodes"`
}

type Worker struct {
	Nodes []string `json:"nodes"`
}

// Features mirrors the subset of cluster.cilium.* toggles downstream gates on.
// Add fields here as new gates arise rather than asking consumers to re-parse
// the Cilium block.
type Features struct {
	GatewayAPI     bool `json:"gatewayAPI"`
	BGP            bool `json:"bgp"`
	Hubble         bool `json:"hubble"`
	Metrics        bool `json:"metrics"`
	ServiceMonitor bool `json:"serviceMonitor"`
}

// From projects a validated bootstrap config onto the stable facts document.
// It never reads from disk; the network CIDR and per-feature flags come
// straight off the config struct.
func From(cfg *config.Config) Facts {
	c := cfg.Cluster
	cp := cfg.ControlPlane

	cpNodes := sortedKeys(cp.Nodes)
	workerNodes := sortedKeys(cfg.Worker.Nodes)

	return Facts{
		SchemaVersion: SchemaVersion,
		Cluster: Cluster{
			Name:   c.Name,
			Domain: c.Domain,
			FQDN:   c.FQDN(c.Name),
		},
		Network: Network{
			IPv4NativeRoutingCIDR: nativeRoutingCIDR(c.Cilium),
		},
		ControlPlane: ControlPlane{
			Record:   cp.Record,
			Endpoint: endpoint(&c, &cp, cpNodes),
			Nodes:    cpNodes,
		},
		Worker:   Worker{Nodes: workerNodes},
		Features: featuresOf(c.Cilium),
	}
}

func sortedKeys(m map[string][]string) []string {
	out := slices.Sorted(maps.Keys(m))
	if out == nil {
		return []string{}
	}
	return out
}

// endpoint returns the cluster API endpoint downstream consumers should
// connect to. With record-as-endpoint the dedicated record (e.g. a VIP or LB
// alias) is used; otherwise we fall back to the first control plane node's
// FQDN. Returns "" if neither path can produce a usable host.
func endpoint(c *config.Cluster, cp *config.ControlPlane, cpNodes []string) string {
	var host string
	switch {
	case cp.RecordAsEndpoint:
		host = c.FQDN(cp.Record)
	case len(cpNodes) > 0:
		host = c.FQDN(cpNodes[0])
	}
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(apiServerPort))
}

func nativeRoutingCIDR(c *config.CiliumConfig) string {
	if c == nil || c.NativeRouting == nil || !c.NativeRouting.Enabled {
		return ""
	}
	return c.NativeRouting.IPv4CIDR
}

func featuresOf(c *config.CiliumConfig) Features {
	if c == nil {
		return Features{}
	}
	return Features{
		GatewayAPI:     c.GatewayAPI != nil && c.GatewayAPI.Enabled,
		BGP:            c.BGP != nil && c.BGP.Enabled,
		Hubble:         c.Hubble != nil && c.Hubble.Enabled,
		Metrics:        c.Metrics != nil && c.Metrics.Enabled,
		ServiceMonitor: serviceMonitorEnabled(c),
	}
}

func serviceMonitorEnabled(c *config.CiliumConfig) bool {
	if c.Metrics != nil && c.Metrics.ServiceMonitor {
		return true
	}
	if c.Hubble != nil && c.Hubble.Metrics != nil && c.Hubble.Metrics.ServiceMonitor {
		return true
	}
	return false
}
