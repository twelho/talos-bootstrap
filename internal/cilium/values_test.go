// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package cilium

import (
	"slices"
	"testing"

	"github.com/twelho/talos-bootstrap/internal/config"
)

func TestValues_BareMinimum(t *testing.T) {
	v := FromConfig(nil, NewTopology(3, 3)).Values(true)

	if got := v["agent"]; got != true {
		t.Errorf("agent: got %v, want true", got)
	}
	if got := v["kubeProxyReplacement"]; got != true {
		t.Errorf("kubeProxyReplacement: got %v, want true", got)
	}
	if got := v["k8sServiceHost"]; got != "localhost" {
		t.Errorf("k8sServiceHost: got %v", got)
	}
	if got := v["policyEnforcementMode"]; got != "always" {
		t.Errorf("default hardening should set policyEnforcementMode=always, got %v", got)
	}
	if got := v["policyAuditMode"]; got != true {
		t.Errorf("default hardening should set policyAuditMode=true, got %v", got)
	}
	if _, ok := v["operator"].(map[string]any)["replicas"]; ok {
		t.Error("operator.replicas should be unset when there are enough nodes")
	}
}

func TestValues_SingleOperatorTopology(t *testing.T) {
	v := FromConfig(nil, NewTopology(1, 0)).Values(true)
	op := v["operator"].(map[string]any)
	if got := op["replicas"]; got != 1 {
		t.Errorf("operator.replicas: got %v, want 1", got)
	}
}

func TestValues_BGPAddsAgentCapability(t *testing.T) {
	v := FromConfig(&config.CiliumConfig{BGP: &config.CiliumBGP{Enabled: true}},
		NewTopology(3, 3)).Values(true)
	caps := v["securityContext"].(map[string]any)["capabilities"].(map[string]any)["ciliumAgent"].([]string)
	if !slices.Contains(caps, "NET_BIND_SERVICE") {
		t.Errorf("BGP must add NET_BIND_SERVICE to ciliumAgent capabilities, got %v", caps)
	}
	if bgp := v["bgpControlPlane"].(map[string]any)["enabled"]; bgp != true {
		t.Errorf("bgpControlPlane.enabled: got %v", bgp)
	}
}

func TestValues_GatewayAPIPrivilegedAddsEnvoyCapability(t *testing.T) {
	v := FromConfig(&config.CiliumConfig{GatewayAPI: &config.CiliumGatewayAPI{
		Enabled:         true,
		PrivilegedPorts: true,
	}}, NewTopology(3, 3)).Values(true)
	envoy := v["envoy"].(map[string]any)
	caps := envoy["securityContext"].(map[string]any)["capabilities"].(map[string]any)["envoy"].([]string)
	if !slices.Contains(caps, "NET_BIND_SERVICE") {
		t.Errorf("privileged-ports must add NET_BIND_SERVICE to envoy capabilities, got %v", caps)
	}
}

func TestValues_MasqueradeDisabledClearsAllThree(t *testing.T) {
	v := FromConfig(&config.CiliumConfig{Masquerade: &config.CiliumMasquerade{Enabled: false}},
		NewTopology(3, 3)).Values(true)
	if got := v["bpf"].(map[string]any)["masquerade"]; got != false {
		t.Errorf("bpf.masquerade: got %v, want false", got)
	}
	if got := v["enableIPv4Masquerade"]; got != false {
		t.Error("enableIPv4Masquerade must be false when masquerade disabled")
	}
	if got := v["enableIPv6Masquerade"]; got != false {
		t.Error("enableIPv6Masquerade must be false when masquerade disabled")
	}
}

func TestValues_HardeningOverrideDisables(t *testing.T) {
	v := FromConfig(&config.CiliumConfig{Hardening: &config.CiliumHardening{Enabled: false, AuditMode: false}},
		NewTopology(3, 3)).Values(true)
	if _, ok := v["policyEnforcementMode"]; ok {
		t.Error("hardening.enabled=false must omit policyEnforcementMode")
	}
	if _, ok := v["policyAuditMode"]; ok {
		t.Error("hardening.audit-mode=false must omit policyAuditMode")
	}
}

func TestValuesYAML_Renders(t *testing.T) {
	data, err := FromConfig(nil, NewTopology(3, 3)).ValuesYAML(true)
	if err != nil {
		t.Fatalf("ValuesYAML: %v", err)
	}
	if len(data) < 200 {
		t.Errorf("ValuesYAML output suspiciously small (%d bytes)", len(data))
	}
}
