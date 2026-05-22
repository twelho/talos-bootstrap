// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package bootstrap

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/twelho/talos-bootstrap/internal/config"
)

func TestNewInitializesDerivedState(t *testing.T) {
	nodes := map[string]string{"cp-b": "10.0.0.2"}
	cfg := testConfig()

	p, err := New(Options{
		Config:         cfg,
		Dir:            t.TempDir(),
		BootstrapNodes: nodes,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	nodes["cp-b"] = "10.0.0.200"
	if got := p.endpointFor("cp-b"); got != "10.0.0.2" {
		t.Fatalf("bootstrap node endpoint was not copied: got %q", got)
	}

	if !slices.Equal(p.cpNodes, []string{"cp-a", "cp-b"}) {
		t.Fatalf("cpNodes: got %v", p.cpNodes)
	}
	if !slices.Equal(p.workerNodes, []string{"worker-a"}) {
		t.Fatalf("workerNodes: got %v", p.workerNodes)
	}
	if p.bootstrapAll {
		t.Fatal("bootstrapAll should be false when only one node is selected")
	}
}

func TestNewRejectsUnknownBootstrapNode(t *testing.T) {
	_, err := New(Options{
		Config:         testConfig(),
		Dir:            t.TempDir(),
		BootstrapNodes: map[string]string{"missing": ""},
	})
	if err == nil {
		t.Fatal("New should reject bootstrap nodes outside the configured topology")
	}
}

// TestPhasesHaveExactlyOneTerminal locks in the contract that exactly one
// phase is marked terminal (the partial-bootstrap stopping point). If a
// future change splits the reboot phase, this test forces the author to
// decide which sibling owns the terminal marker.
func TestPhasesHaveExactlyOneTerminal(t *testing.T) {
	p, err := New(Options{Config: testConfig(), Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var terminal []string
	for _, ph := range p.phases() {
		if ph.terminal {
			terminal = append(terminal, ph.name)
		}
	}
	if len(terminal) != 1 {
		t.Fatalf("expected exactly one terminal phase, got %v", terminal)
	}
	if terminal[0] != "reboot bootstrapped nodes" {
		t.Errorf("terminal phase changed name to %q; update --skip-cluster-configuration docs if intentional", terminal[0])
	}
}

func TestValidateBootstrapNodes_AllNodesEnablesBootstrapAll(t *testing.T) {
	cfg := testConfig()
	all := map[string]string{"cp-a": "", "cp-b": "", "worker-a": ""}
	p, err := New(Options{Config: cfg, Dir: t.TempDir(), BootstrapNodes: all})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !p.bootstrapAll {
		t.Error("bootstrapAll should be true when every node is listed")
	}
}

func TestResolvePatchesAndPaths(t *testing.T) {
	dir := "/tmp/cluster"
	p := &Pipeline{dir: dir}

	if got, want := p.resolvePath("secrets.yaml"), filepath.Join(dir, "secrets.yaml"); got != want {
		t.Errorf("relative path: got %q, want %q", got, want)
	}
	if got, want := p.resolvePath("/abs/path"), "/abs/path"; got != want {
		t.Errorf("absolute path must pass through: got %q, want %q", got, want)
	}
	if got := p.resolvePath(""); got != "" {
		t.Errorf("empty path must pass through, got %q", got)
	}

	in := []string{
		`[{"op":"add"}]`,
		"@patch/example.yaml",
		"@/abs/patch.yaml",
	}
	out := p.resolvePatches(in)
	if out[0] != in[0] {
		t.Errorf("inline patch must pass through: got %q", out[0])
	}
	if want := "@" + filepath.Join(dir, "patch/example.yaml"); out[1] != want {
		t.Errorf("relative @-patch: got %q, want %q", out[1], want)
	}
	if out[2] != "@/abs/patch.yaml" {
		t.Errorf("absolute @-patch must pass through: got %q", out[2])
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
