// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package facts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/twelho/talos-bootstrap/internal/config"
)

// TestFrom_GoldenExample locks in the exact JSON shape downstream consumers
// will see. The fixture lives in testdata/example.golden.json and mirrors
// clusters/example.yaml; refactors that rename a key must update both the
// type and the golden file together.
func TestFrom_GoldenExample(t *testing.T) {
	cfg := &config.Config{
		Cluster: config.Cluster{
			Name:   "my-cluster",
			Domain: "example.com",
			Cilium: &config.CiliumConfig{
				Metrics: &config.CiliumMetrics{Enabled: false, ServiceMonitor: false},
				Hubble: &config.CiliumHubble{
					Enabled: false,
					Metrics: &config.CiliumHubbleMetrics{Enabled: false, ServiceMonitor: false},
				},
				GatewayAPI:    &config.CiliumGatewayAPI{Enabled: false},
				BGP:           &config.CiliumBGP{Enabled: true},
				NativeRouting: &config.CiliumNativeRouting{Enabled: true, IPv4CIDR: "10.244.0.0/16"},
			},
		},
		ControlPlane: config.ControlPlane{
			Record:           "my-cluster-control-plane",
			RecordAsEndpoint: false,
			Nodes: map[string][]string{
				"talos-master-1": nil,
				"talos-master-2": nil,
				"talos-master-3": nil,
			},
		},
		Worker: config.Worker{
			Nodes: map[string][]string{
				"talos-worker-1": nil,
				"talos-worker-2": nil,
				"talos-worker-3": nil,
			},
		},
	}

	got, err := json.MarshalIndent(From(cfg), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	want, err := os.ReadFile(filepath.Join("testdata", "example.golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("facts JSON drifted from golden. Got:\n%s\nWant:\n%s", got, want)
	}
}

func TestFrom_EndpointFallsBackToFirstNodeWhenRecordNotEndpoint(t *testing.T) {
	cfg := &config.Config{
		Cluster: config.Cluster{Name: "c", Domain: "example.com"},
		ControlPlane: config.ControlPlane{
			Record:           "api",
			RecordAsEndpoint: false,
			Nodes:            map[string][]string{"cp-a": nil, "cp-b": nil},
		},
	}
	got := From(cfg).ControlPlane.Endpoint
	if got != "cp-a.example.com:6443" {
		t.Errorf("endpoint must fall back to sorted first CP node, got %q", got)
	}
}

func TestFrom_EndpointUsesRecordWhenRecordAsEndpoint(t *testing.T) {
	cfg := &config.Config{
		Cluster: config.Cluster{Name: "c", Domain: "example.com"},
		ControlPlane: config.ControlPlane{
			Record:           "api",
			RecordAsEndpoint: true,
			Nodes:            map[string][]string{"cp-a": nil},
		},
	}
	got := From(cfg).ControlPlane.Endpoint
	if got != "api.example.com:6443" {
		t.Errorf("endpoint should use record, got %q", got)
	}
}

func TestFrom_EmptyNodesEmitAsEmptyArray(t *testing.T) {
	cfg := &config.Config{
		Cluster:      config.Cluster{Name: "c"},
		ControlPlane: config.ControlPlane{Nodes: map[string][]string{}},
		Worker:       config.Worker{Nodes: nil},
	}
	got, err := json.Marshal(From(cfg))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Both node lists must serialize as [] (not null) so Nix fromJSON yields
	// a list type unconditionally.
	if !bytes.Contains(got, []byte(`"nodes":[]`)) {
		t.Errorf("nodes lists must serialize as []: %s", got)
	}
}

func TestFrom_ServiceMonitorOnFromHubbleAlone(t *testing.T) {
	cfg := &config.Config{
		Cluster: config.Cluster{
			Name: "c",
			Cilium: &config.CiliumConfig{
				Hubble: &config.CiliumHubble{
					Enabled: true,
					Metrics: &config.CiliumHubbleMetrics{Enabled: true, ServiceMonitor: true},
				},
			},
		},
		ControlPlane: config.ControlPlane{Nodes: map[string][]string{"cp": nil}},
	}
	if !From(cfg).Features.ServiceMonitor {
		t.Error("hubble.metrics.servicemonitor alone must set features.serviceMonitor=true")
	}
}
