// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package talos wraps the Talos machinery SDK with a lean, intent-shaped
// surface tailored to the bootstrap workflow: generate config, apply config,
// bootstrap, reboot, observe boot stage, fetch kubeconfig, and health-check.
//
// All exposed operations take an explicit context and explicit node addresses.
// Insecure (maintenance) mode is selected per-call rather than baked into the
// long-lived service value, because talos-bootstrap typically alternates
// between un-bootstrapped nodes (insecure) and a healthy cluster (TLS) within
// a single run.
package talos

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	clientconfig "github.com/siderolabs/talos/pkg/machinery/client/config"
	"github.com/siderolabs/talos/pkg/machinery/config"
	"github.com/siderolabs/talos/pkg/machinery/config/configpatcher"
	"github.com/siderolabs/talos/pkg/machinery/config/generate"
	"github.com/siderolabs/talos/pkg/machinery/config/generate/secrets"
	"github.com/siderolabs/talos/pkg/machinery/config/machine"
)

type GenerateRequest struct {
	ClusterName     string
	Endpoint        string
	SecretsPath     string
	InstallImage    string
	Patches         []string
	Endpoints       []string
	DefaultNode     string
	OutputDir       string
	TalosconfigPath string
}

type GenerateResult struct {
	ControlPlaneFile string
	WorkerFile       string
	TalosconfigFile  string
}

// Generate writes the three artifacts that `talosctl gen config` produces:
// controlplane.yaml, worker.yaml, and a talosconfig referencing the requested
// endpoints. Cluster-wide patches are applied to both machine configs.
//
// Files are written relative to req.OutputDir, which is interpreted against
// the process working directory. Callers that want artifacts in a specific
// location must chdir or pass an absolute path: Generate itself does not
// mutate cwd.
func Generate(req GenerateRequest) (*GenerateResult, error) {
	bundle, err := secrets.LoadBundle(req.SecretsPath)
	if err != nil {
		return nil, fmt.Errorf("load secrets bundle %q: %w", req.SecretsPath, err)
	}

	opts := []generate.Option{
		generate.WithVersionContract(config.TalosVersionCurrent),
		generate.WithSecretsBundle(bundle),
	}
	if req.InstallImage != "" {
		opts = append(opts, generate.WithInstallImage(req.InstallImage))
	}
	if len(req.Endpoints) > 0 {
		opts = append(opts, generate.WithEndpointList(req.Endpoints))
	}

	input, err := generate.NewInput(req.ClusterName, req.Endpoint, "", opts...)
	if err != nil {
		return nil, fmt.Errorf("build generate input: %w", err)
	}

	patches, err := configpatcher.LoadPatches(req.Patches)
	if err != nil {
		return nil, fmt.Errorf("load patches: %w", err)
	}

	cpFile, err := writeMachineConfig(input, machine.TypeControlPlane, patches,
		filepath.Join(req.OutputDir, "controlplane.yaml"))
	if err != nil {
		return nil, fmt.Errorf("control plane config: %w", err)
	}
	workerFile, err := writeMachineConfig(input, machine.TypeWorker, patches,
		filepath.Join(req.OutputDir, "worker.yaml"))
	if err != nil {
		return nil, fmt.Errorf("worker config: %w", err)
	}

	tc, err := input.Talosconfig()
	if err != nil {
		return nil, fmt.Errorf("generate talosconfig: %w", err)
	}
	if req.DefaultNode != "" {
		for _, ctx := range tc.Contexts {
			ctx.Nodes = []string{req.DefaultNode}
		}
	}
	tcPath := req.TalosconfigPath
	if tcPath == "" {
		tcPath = filepath.Join(req.OutputDir, "talosconfig")
	}
	if err := tc.Save(tcPath); err != nil {
		return nil, fmt.Errorf("save talosconfig: %w", err)
	}

	return &GenerateResult{
		ControlPlaneFile: cpFile,
		WorkerFile:       workerFile,
		TalosconfigFile:  tcPath,
	}, nil
}

// MergeTalosconfig folds src into the Talos client config at dst (creating
// dst if missing). An empty dst resolves to the first writable default
// talosconfig path ($TALOSCONFIG or ~/.talos/config), matching
// `talosctl config merge`. The Talos client's Save handles the directory
// creation and 0600 file mode, so this wrapper does not reapply them.
func MergeTalosconfig(src, dst string) error {
	if dst == "" {
		resolved, err := defaultTalosconfigPath()
		if err != nil {
			return fmt.Errorf("resolve default talosconfig path: %w", err)
		}
		dst = resolved
	}
	srcCfg, err := clientconfig.Open(src)
	if err != nil {
		return fmt.Errorf("read source talosconfig: %w", err)
	}
	dstCfg, err := openOrEmptyTalosconfig(dst)
	if err != nil {
		return fmt.Errorf("read destination talosconfig: %w", err)
	}
	dstCfg.Merge(srcCfg)
	if err := dstCfg.Save(dst); err != nil {
		return fmt.Errorf("write talosconfig: %w", err)
	}
	return nil
}

// defaultTalosconfigPath returns the first writable path in the Talos client's
// default lookup order. Surfacing the resolution at the boundary (rather than
// relying on Save("")) makes the failure mode explicit and stable against
// SDK changes.
func defaultTalosconfigPath() (string, error) {
	paths, err := clientconfig.GetDefaultPaths()
	if err != nil {
		return "", err
	}
	for _, p := range paths {
		if p.WriteAllowed {
			return p.Path, nil
		}
	}
	return "", fmt.Errorf("no writable talosconfig path found")
}

func writeMachineConfig(in *generate.Input, t machine.Type, patches []configpatcher.Patch, out string) (string, error) {
	cfg, err := in.Config(t)
	if err != nil {
		return "", err
	}
	if len(patches) > 0 {
		patched, err := configpatcher.Apply(configpatcher.WithConfig(cfg), patches)
		if err != nil {
			return "", fmt.Errorf("apply cluster patches: %w", err)
		}
		data, err := patched.Bytes()
		if err != nil {
			return "", fmt.Errorf("marshal patched config: %w", err)
		}
		return out, os.WriteFile(out, data, 0o600)
	}
	data, err := cfg.Bytes()
	if err != nil {
		return "", fmt.Errorf("marshal config: %w", err)
	}
	return out, os.WriteFile(out, data, 0o600)
}

// openOrEmptyTalosconfig loads a talosconfig file, returning an empty config
// (rather than an error) if the file does not yet exist. This is the right
// shape for "merge into the user's config, creating it if necessary".
func openOrEmptyTalosconfig(path string) (*clientconfig.Config, error) {
	cfg, err := clientconfig.Open(path)
	if err == nil {
		return cfg, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return &clientconfig.Config{Contexts: map[string]*clientconfig.Context{}}, nil
	}
	return nil, err
}
