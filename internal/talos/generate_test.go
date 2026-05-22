// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package talos

import (
	"os"
	"path/filepath"
	"testing"

	clientconfig "github.com/siderolabs/talos/pkg/machinery/client/config"
)

func TestMergeTalosconfig_CreatesAndMerges(t *testing.T) {
	dir := t.TempDir()

	src := filepath.Join(dir, "src.yaml")
	srcCfg := &clientconfig.Config{
		Context: "src",
		Contexts: map[string]*clientconfig.Context{
			"src": {Endpoints: []string{"127.0.0.1:50000"}},
		},
	}
	if err := srcCfg.Save(src); err != nil {
		t.Fatalf("save src: %v", err)
	}

	dst := filepath.Join(dir, "merged.yaml")
	if err := MergeTalosconfig(src, dst); err != nil {
		t.Fatalf("MergeTalosconfig: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("dst not written: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("dst mode = %o, want 0600", info.Mode().Perm())
	}

	merged, err := clientconfig.Open(dst)
	if err != nil {
		t.Fatalf("open merged: %v", err)
	}
	if _, ok := merged.Contexts["src"]; !ok {
		t.Errorf("src context missing after merge; contexts: %v", merged.Contexts)
	}
}

func TestMergeTalosconfig_IntoExistingDst(t *testing.T) {
	dir := t.TempDir()

	src := filepath.Join(dir, "src.yaml")
	if err := (&clientconfig.Config{
		Context: "src",
		Contexts: map[string]*clientconfig.Context{
			"src": {Endpoints: []string{"1.1.1.1:50000"}},
		},
	}).Save(src); err != nil {
		t.Fatalf("save src: %v", err)
	}

	dst := filepath.Join(dir, "dst.yaml")
	if err := (&clientconfig.Config{
		Context: "existing",
		Contexts: map[string]*clientconfig.Context{
			"existing": {Endpoints: []string{"2.2.2.2:50000"}},
		},
	}).Save(dst); err != nil {
		t.Fatalf("save dst: %v", err)
	}

	if err := MergeTalosconfig(src, dst); err != nil {
		t.Fatalf("MergeTalosconfig: %v", err)
	}

	merged, err := clientconfig.Open(dst)
	if err != nil {
		t.Fatalf("open merged: %v", err)
	}
	for _, want := range []string{"src", "existing"} {
		if _, ok := merged.Contexts[want]; !ok {
			t.Errorf("merged config missing %q context", want)
		}
	}
}
