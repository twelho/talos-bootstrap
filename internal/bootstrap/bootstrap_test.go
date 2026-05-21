// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package bootstrap

import (
	"testing"
	"time"

	"github.com/twelho/talos-bootstrap/internal/config"
)

func TestNewInitializesDerivedState(t *testing.T) {
	nodes := map[string]string{"cp-b": "10.0.0.2"}
	cfg := testConfig()

	b, err := New(BootstrapOptions{
		Config:         cfg,
		BootstrapNodes: nodes,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	nodes["cp-b"] = "10.0.0.200"
	if got := b.endpointFor("cp-b"); got != "10.0.0.2" {
		t.Fatalf("bootstrap node endpoint was not copied: got %q", got)
	}

	if got, want := b.cpNodes, []string{"cp-a", "cp-b"}; got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("cpNodes: got %v, want %v", got, want)
	}
	if got, want := b.workerNodes, []string{"worker-a"}; got[0] != want[0] {
		t.Fatalf("workerNodes: got %v, want %v", got, want)
	}
	if b.bootstrapAll {
		t.Fatal("bootstrapAll should be false when only one node is selected")
	}
	if b.bootstrapRetry != 5*time.Second {
		t.Fatalf("bootstrapRetry default: got %s", b.bootstrapRetry)
	}
	if b.healthTimeout != 10*time.Minute {
		t.Fatalf("healthTimeout default: got %s", b.healthTimeout)
	}
	if b.ciliumOptions() != b.ciliumOpts {
		t.Fatal("ciliumOptions should return constructor-initialized options")
	}
}

func TestNewRejectsUnknownBootstrapNode(t *testing.T) {
	_, err := New(BootstrapOptions{
		Config:         testConfig(),
		BootstrapNodes: map[string]string{"missing": ""},
	})
	if err == nil {
		t.Fatal("New should reject bootstrap nodes outside the configured topology")
	}
}

func testConfig() *config.Config {
	return &config.Config{
		Cluster: config.Cluster{
			Name:    "test",
			Domain:  "example.com",
			Secrets: "secrets.yaml",
		},
		ControlPlane: config.ControlPlane{
			Record: "api",
			Nodes: map[string][]string{
				"cp-b": nil,
				"cp-a": nil,
			},
		},
		Worker: config.Worker{
			Nodes: map[string][]string{"worker-a": nil},
		},
	}
}
