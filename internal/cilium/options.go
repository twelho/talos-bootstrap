// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package cilium owns the typed model of every Cilium installation knob this
// project exposes. Options is the single source of truth: it is derived from a
// user's Cluster.Cilium config plus cluster topology, and renders down to the
// Helm values consumed by the Cilium chart. The same model is intended to drive
// a future "emit values.yaml for external consumers" path without reproducing
// the conditional logic anywhere else.
//
// Pointer fields denote tri-state knobs where absence means "leave the chart
// defaults alone". Non-pointer fields are always rendered.
package cilium

import "github.com/twelho/talos-bootstrap/internal/config"

type Options struct {
	Metrics       *Metrics
	Hubble        *Hubble
	Hardening     Hardening
	GatewayAPI    *GatewayAPI
	NodeIPAM      *NodeIPAM
	NativeRouting *NativeRouting
	Netkit        bool
	BGP           *BGP
	Masquerade    *Masquerade
	// SingleOperator forces operator.replicas=1 when the topology cannot
	// reliably schedule two operator pods.
	SingleOperator bool
}

type Metrics struct {
	Enabled        bool
	ServiceMonitor bool
}

type Hubble struct {
	Enabled bool
	Metrics *HubbleMetrics
	Export  *HubbleExport
}

type HubbleMetrics struct {
	Enabled        bool
	ServiceMonitor bool
}

type HubbleExport struct {
	Enabled bool
	Path    string
}

type Hardening struct {
	Enabled   bool
	AuditMode bool
}

type GatewayAPI struct {
	Enabled         bool
	HostNetwork     bool
	PrivilegedPorts bool
}

type NodeIPAM struct {
	Enabled bool
}

type NativeRouting struct {
	Enabled      bool
	IPv4CIDR     string
	DirectRoutes bool
}

type BGP struct {
	Enabled bool
}

type Masquerade struct {
	Enabled bool
	BPF     bool
}

// Topology summarises the node count facts the option model needs. Keeping it
// explicit lets callers compute it once and avoids dragging the full Config
// into the renderer.
type Topology struct {
	controlPlanes int
	workers       int
}

func NewTopology(controlPlanes, workers int) Topology {
	return Topology{
		controlPlanes: controlPlanes,
		workers:       workers,
	}
}

func TopologyFromConfig(cfg *config.Config) Topology {
	if cfg == nil {
		return NewTopology(0, 0)
	}
	return NewTopology(len(cfg.ControlPlane.Nodes), len(cfg.Worker.Nodes))
}

// FromConfig translates a validated Cluster.Cilium block plus topology into a
// fully resolved Options value, applying the implicit defaults (hardening on,
// audit mode on, single-operator topology heuristic) so the renderer never
// has to know about absent blocks.
func FromConfig(c *config.CiliumConfig, t Topology) Options {
	opts := Options{
		Hardening: Hardening{Enabled: true, AuditMode: true},
	}

	if t.workers == 1 || (t.workers == 0 && t.controlPlanes == 1) {
		opts.SingleOperator = true
	}

	if c == nil {
		return opts
	}

	if c.Metrics != nil {
		opts.Metrics = &Metrics{
			Enabled:        c.Metrics.Enabled,
			ServiceMonitor: c.Metrics.ServiceMonitor,
		}
	}

	if c.Hubble != nil {
		opts.Hubble = &Hubble{Enabled: c.Hubble.Enabled}
		if c.Hubble.Metrics != nil {
			opts.Hubble.Metrics = &HubbleMetrics{
				Enabled:        c.Hubble.Metrics.Enabled,
				ServiceMonitor: c.Hubble.Metrics.ServiceMonitor,
			}
		}
		if c.Hubble.Export != nil {
			opts.Hubble.Export = &HubbleExport{
				Enabled: c.Hubble.Export.Enabled,
				Path:    c.Hubble.Export.Path,
			}
		}
	}

	if c.Hardening != nil {
		opts.Hardening = Hardening{
			Enabled:   c.Hardening.Enabled,
			AuditMode: c.Hardening.AuditMode,
		}
	}

	if c.GatewayAPI != nil {
		opts.GatewayAPI = &GatewayAPI{
			Enabled:         c.GatewayAPI.Enabled,
			HostNetwork:     c.GatewayAPI.HostNetwork,
			PrivilegedPorts: c.GatewayAPI.PrivilegedPorts,
		}
	}

	if c.NodeIPAM != nil {
		opts.NodeIPAM = &NodeIPAM{Enabled: c.NodeIPAM.Enabled}
	}

	if c.NativeRouting != nil {
		opts.NativeRouting = &NativeRouting{
			Enabled:      c.NativeRouting.Enabled,
			IPv4CIDR:     c.NativeRouting.IPv4CIDR,
			DirectRoutes: c.NativeRouting.DirectRoutes,
		}
	}

	opts.Netkit = c.Netkit

	if c.BGP != nil {
		opts.BGP = &BGP{Enabled: c.BGP.Enabled}
	}

	if c.Masquerade != nil {
		opts.Masquerade = &Masquerade{
			Enabled: c.Masquerade.Enabled,
			BPF:     c.Masquerade.BPFEnabled(),
		}
	}

	return opts
}

// GatewayAPIEnabled is a convenience for orchestrator code that needs to know
// whether to install the Gateway API CRDs and restart the Cilium operator
// after install.
func (o Options) GatewayAPIEnabled() bool {
	return o.GatewayAPI != nil && o.GatewayAPI.Enabled
}
