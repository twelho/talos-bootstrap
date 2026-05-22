// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package cilium reads the typed Cilium block from the cluster config and
// renders it down to the Helm values consumed by the Cilium chart. The
// renderer operates directly on config.CiliumConfig; the only non-config
// input is Topology, which decides the single-operator heuristic.
package cilium

import "github.com/twelho/talos-bootstrap/internal/config"

// Options is the renderer input. It wraps the user-supplied Cilium block (may
// be nil) and the cluster topology. Computed accessors below encode the
// implicit defaults so the renderer never has to reason about absent blocks.
type Options struct {
	Cilium   *config.CiliumConfig
	Topology Topology
}

// Topology summarises the node count facts the option model needs. Keeping
// it explicit lets callers compute it once and avoids dragging the full
// Config into the renderer.
type Topology struct {
	controlPlanes int
	workers       int
}

func NewTopology(controlPlanes, workers int) Topology {
	return Topology{controlPlanes: controlPlanes, workers: workers}
}

func TopologyFromConfig(cfg *config.Config) Topology {
	if cfg == nil {
		return NewTopology(0, 0)
	}
	return NewTopology(len(cfg.ControlPlane.Nodes), len(cfg.Worker.Nodes))
}

// FromConfig wires a Cilium block and a topology into the renderer input.
// No defaulting happens here; the accessors below apply defaults at use time.
func FromConfig(c *config.CiliumConfig, t Topology) Options {
	return Options{Cilium: c, Topology: t}
}

// GatewayAPIEnabled is a convenience for orchestrator code that needs to know
// whether to install the Gateway API CRDs and restart the Cilium operator
// after install.
func (o Options) GatewayAPIEnabled() bool {
	return o.Cilium != nil && o.Cilium.GatewayAPI != nil && o.Cilium.GatewayAPI.Enabled
}

// GatewayAPIVersion returns the pinned gateway-api release (e.g. "v1.4.0").
// Empty means "auto-resolve from Cilium's go.mod".
func (o Options) GatewayAPIVersion() string {
	if o.Cilium == nil || o.Cilium.GatewayAPI == nil {
		return ""
	}
	return o.Cilium.GatewayAPI.Version
}

// singleOperator returns true when the topology cannot reliably schedule two
// Cilium operator pods (single-worker or single-CP-only clusters).
func (o Options) singleOperator() bool {
	return o.Topology.workers == 1 || (o.Topology.workers == 0 && o.Topology.controlPlanes == 1)
}

// hardeningEnabled defaults to true: a NetworkPolicy-enforced posture is the
// safer choice when the user hasn't opted out.
func (o Options) hardeningEnabled() bool {
	if o.Cilium == nil || o.Cilium.Hardening == nil {
		return true
	}
	return o.Cilium.Hardening.Enabled
}

// hardeningAuditMode also defaults to true: audit-mode lets a fresh cluster
// boot before any NetworkPolicies have been declared without locking the user
// out. Production must turn this off after policies are in place.
func (o Options) hardeningAuditMode() bool {
	if o.Cilium == nil || o.Cilium.Hardening == nil {
		return true
	}
	return o.Cilium.Hardening.AuditMode
}
