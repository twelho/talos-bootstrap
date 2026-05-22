// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package bootstrap orchestrates the talos -> kube -> cilium -> gateway-api ->
// sops -> flux -> manifests -> health sequence as an ordered list of phases.
// Run executes them sequentially and stops on the first error.
package bootstrap

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/twelho/talos-bootstrap/internal/cilium"
	"github.com/twelho/talos-bootstrap/internal/config"
	"github.com/twelho/talos-bootstrap/internal/helm"
	"github.com/twelho/talos-bootstrap/internal/kube"
	"github.com/twelho/talos-bootstrap/internal/talos"
)

const (
	systemNamespace  = "kube-system"
	ciliumRepoName   = "cilium"
	ciliumRepoURL    = "https://helm.cilium.io/"
	ciliumChart      = "cilium/cilium"
	apiServerPort    = 6443
	bootstrapRetry   = 5 * time.Second
	healthTimeout    = 10 * time.Minute
	postRebootSettle = 5 * time.Second
	apiServerSettle  = 5 * time.Second
)

// Pipeline owns the bootstrap state for a single run: the parsed config, the
// directory all relative paths resolve against, the derived topology, and the
// service clients that each phase progressively populates. Service fields are
// nil until the phase that constructs them runs; this is enforced by the
// linear order in phases() rather than by the type system.
type Pipeline struct {
	cfg                      *config.Config
	dir                      string
	bootstrapNodes           map[string]string // node -> override endpoint (or "")
	skipClusterConfiguration bool
	ciliumOpts               cilium.Options
	cpNodes                  []string
	workerNodes              []string
	bootstrapAll             bool

	talosService *talos.Service
	kubeClient   *kube.Client
	helmClient   *helm.Client
}

type Options struct {
	Config *config.Config
	// Dir is the directory all relative paths in Config resolve against
	// (typically the directory containing the config file). It is also used
	// as the output directory for generated Talos artifacts.
	Dir                      string
	BootstrapNodes           map[string]string
	SkipClusterConfiguration bool
}

func New(opts Options) (*Pipeline, error) {
	if opts.Config == nil {
		return nil, fmt.Errorf("bootstrap config is required")
	}
	if opts.Dir == "" {
		return nil, fmt.Errorf("bootstrap dir is required")
	}

	bootstrapNodes := maps.Clone(opts.BootstrapNodes)
	if bootstrapNodes == nil {
		bootstrapNodes = map[string]string{}
	}

	cpNodes := slices.Sorted(maps.Keys(opts.Config.ControlPlane.Nodes))
	workerNodes := slices.Sorted(maps.Keys(opts.Config.Worker.Nodes))
	if err := validateBootstrapNodes(bootstrapNodes, cpNodes, workerNodes); err != nil {
		return nil, err
	}

	return &Pipeline{
		cfg:                      opts.Config,
		dir:                      opts.Dir,
		bootstrapNodes:           bootstrapNodes,
		skipClusterConfiguration: opts.SkipClusterConfiguration,
		ciliumOpts: cilium.FromConfig(opts.Config.Cluster.Cilium,
			cilium.NewTopology(len(cpNodes), len(workerNodes))),
		cpNodes:      cpNodes,
		workerNodes:  workerNodes,
		bootstrapAll: bootstrapsAllNodes(bootstrapNodes, cpNodes, workerNodes),
	}, nil
}

// Run executes every phase in sequence. The bootstrap process is not
// idempotent across phase boundaries, so partial recovery is the user's
// responsibility.
func (p *Pipeline) Run(ctx context.Context) error {
	for _, ph := range p.phases() {
		log.Info().Str("phase", ph.name).Msg("starting phase")
		if err := ph.run(ctx); err != nil {
			return fmt.Errorf("%s: %w", ph.name, err)
		}
		if p.skipClusterConfiguration && ph.terminal {
			log.Info().Msg("--skip-cluster-configuration set; stopping after Talos bootstrap")
			return nil
		}
	}
	return nil
}

type phase struct {
	name     string
	run      func(context.Context) error
	terminal bool
}

// phases returns the ordered list of bootstrap steps. Exactly one phase is
// marked terminal: it is the last point at which a partial bootstrap
// (--skip-cluster-configuration) is still well-defined.
func (p *Pipeline) phases() []phase {
	return []phase{
		{name: "generate Talos config", run: p.phaseGenerateConfig},
		{name: "apply control plane config", run: p.phaseApplyControlPlane},
		{name: "apply worker config", run: p.phaseApplyWorker},
		{name: "bootstrap etcd", run: p.phaseBootstrapEtcd},
		{name: "reboot bootstrapped nodes", run: p.phaseRebootBootstrapped, terminal: true},
		{name: "wait for kube API", run: p.phaseWaitKubeAPI},
		{name: "fetch kubeconfig", run: p.phaseKubeconfig},
		{name: "clean up Flannel", run: p.phaseCleanupFlannel},
		{name: "clean up kube-proxy", run: p.phaseCleanupKubeProxy},
		{name: "install monitoring CRDs", run: p.phaseMonitoringCRDs},
		{name: "install Cilium", run: p.phaseCilium},
		{name: "install Gateway API CRDs", run: p.phaseGatewayCRDs},
		{name: "configure SOPS", run: p.phaseSOPS},
		{name: "install Flux", run: p.phaseFlux},
		{name: "apply post-bootstrap manifests", run: p.phasePostManifests},
		{name: "restart Cilium for Gateway API", run: p.phaseRestartCilium},
		{name: "cluster health check", run: p.phaseHealth},
	}
}

// validateBootstrapNodes rejects --bootstrap entries that do not match a
// node declared in the cluster config.
func validateBootstrapNodes(bootstrapNodes map[string]string, cpNodes, workerNodes []string) error {
	known := allNodes(cpNodes, workerNodes)
	for n := range bootstrapNodes {
		if _, ok := known[n]; !ok {
			return fmt.Errorf("unknown node in --bootstrap: %s", n)
		}
	}
	return nil
}

// bootstrapsAllNodes reports whether the caller asked to bootstrap every node
// in the topology. Etcd is initialized only in this case; partial bootstraps
// are assumed to be joining an already-running cluster.
func bootstrapsAllNodes(bootstrapNodes map[string]string, cpNodes, workerNodes []string) bool {
	known := allNodes(cpNodes, workerNodes)
	return len(bootstrapNodes) > 0 && len(bootstrapNodes) == len(known)
}

func allNodes(cpNodes, workerNodes []string) map[string]struct{} {
	known := make(map[string]struct{}, len(cpNodes)+len(workerNodes))
	for _, n := range cpNodes {
		known[n] = struct{}{}
	}
	for _, n := range workerNodes {
		known[n] = struct{}{}
	}
	return known
}

func (p *Pipeline) fqdn(parts ...string) string {
	return p.cfg.Cluster.FQDN(parts...)
}

func (p *Pipeline) endpointFor(node string) string {
	if ep, ok := p.bootstrapNodes[node]; ok && ep != "" {
		return ep
	}
	return p.fqdn(node)
}

func (p *Pipeline) isBootstrapping(node string) bool {
	_, ok := p.bootstrapNodes[node]
	return ok
}

func (p *Pipeline) controlPlaneFQDNs() []string { return p.fqdns(p.cpNodes) }
func (p *Pipeline) workerFQDNs() []string       { return p.fqdns(p.workerNodes) }

func (p *Pipeline) fqdns(nodes []string) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = p.fqdn(n)
	}
	return out
}

// resolvePath joins relative paths against the pipeline's working directory.
// Absolute and empty paths are returned unchanged.
func (p *Pipeline) resolvePath(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(p.dir, path)
}

// resolvePatches rewrites @-prefixed file references in a patch list so they
// resolve against the pipeline's working directory rather than the process
// cwd. Inline JSON/YAML patches are passed through unchanged. The bare-
// filename heuristic that configpatcher.LoadPatches also supports is
// intentionally not handled here: every example uses the explicit @ form.
func (p *Pipeline) resolvePatches(patches []string) []string {
	out := make([]string, len(patches))
	for i, raw := range patches {
		if strings.HasPrefix(raw, "@") {
			out[i] = "@" + p.resolvePath(raw[1:])
			continue
		}
		out[i] = raw
	}
	return out
}

func (p *Pipeline) waitStageMaintenance(ctx context.Context, node string) error {
	ep := p.endpointFor(node)
	log.Info().Str("node", node).Str("stage", talos.StageMaintenance.String()).Msg("waiting for node stage")
	return p.talosService.WaitStage(ctx, ep, talos.StageMaintenance, talos.StageOpts{
		Endpoint: ep,
		Insecure: true,
	})
}

func (p *Pipeline) waitStageRunning(ctx context.Context, node string) error {
	target := p.fqdn(node)
	log.Info().Str("node", node).Str("stage", talos.StageRunning.String()).Msg("waiting for node stage")
	return p.talosService.WaitStage(ctx, target, talos.StageRunning, talos.StageOpts{})
}

func (p *Pipeline) waitStageForApply(ctx context.Context, node string) error {
	if p.isBootstrapping(node) {
		return p.waitStageMaintenance(ctx, node)
	}
	return p.waitStageRunning(ctx, node)
}
