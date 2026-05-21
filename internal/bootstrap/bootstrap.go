// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package bootstrap is the orchestrator: it sequences the talos -> kube ->
// cilium -> gateway-api -> sops -> flux -> manifests -> health pipeline.
// Each step is its own method to keep the call sites readable and to give
// future versions a place to hang reconciliation, parallelism, or partial
// runs without rewriting Run.
package bootstrap

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/twelho/talos-bootstrap/internal/cilium"
	"github.com/twelho/talos-bootstrap/internal/config"
	"github.com/twelho/talos-bootstrap/internal/helm"
	"github.com/twelho/talos-bootstrap/internal/kube"
	"github.com/twelho/talos-bootstrap/internal/talos"
	"github.com/twelho/talos-bootstrap/internal/util"
)

const (
	ciliumRepoName = "cilium"
	ciliumRepoURL  = "https://helm.cilium.io/"
	ciliumChart    = "cilium/cilium"
	apiServerPort  = 6443
)

// Bootstrap holds the fully resolved inputs needed to run the pipeline.
type Bootstrap struct {
	cfg                      *config.Config
	bootstrapNodes           map[string]string // node -> override endpoint (or "")
	skipClusterConfiguration bool
	bootstrapRetry           time.Duration
	healthTimeout            time.Duration
	ciliumOpts               cilium.Options
	cpNodes                  []string
	workerNodes              []string
	bootstrapAll             bool
}

type BootstrapOptions struct {
	Config                   *config.Config
	BootstrapNodes           map[string]string
	SkipClusterConfiguration bool
	BootstrapRetry           time.Duration
	HealthTimeout            time.Duration
}

func New(opts BootstrapOptions) (*Bootstrap, error) {
	if opts.Config == nil {
		return nil, fmt.Errorf("bootstrap config is required")
	}

	bootstrapNodes := maps.Clone(opts.BootstrapNodes)
	if bootstrapNodes == nil {
		bootstrapNodes = map[string]string{}
	}

	cpNodes := slices.Sorted(maps.Keys(opts.Config.ControlPlane.Nodes))
	workerNodes := slices.Sorted(maps.Keys(opts.Config.Worker.Nodes))
	bootstrapAll, err := validateBootstrapNodes(bootstrapNodes, cpNodes, workerNodes)
	if err != nil {
		return nil, err
	}

	bootstrapRetry := opts.BootstrapRetry
	if bootstrapRetry == 0 {
		bootstrapRetry = 5 * time.Second
	}
	healthTimeout := opts.HealthTimeout
	if healthTimeout == 0 {
		healthTimeout = 10 * time.Minute
	}

	return &Bootstrap{
		cfg:                      opts.Config,
		bootstrapNodes:           bootstrapNodes,
		skipClusterConfiguration: opts.SkipClusterConfiguration,
		bootstrapRetry:           bootstrapRetry,
		healthTimeout:            healthTimeout,
		ciliumOpts: cilium.FromConfig(opts.Config.Cluster.Cilium,
			cilium.NewTopology(len(cpNodes), len(workerNodes))),
		cpNodes:      cpNodes,
		workerNodes:  workerNodes,
		bootstrapAll: bootstrapAll,
	}, nil
}

// Run executes every phase in sequence. Returning early on the first error is
// intentional: the bootstrap process is not idempotent across phase boundaries
// (yet), so partial recovery is the user's responsibility.
func (b *Bootstrap) Run(ctx context.Context) error {
	var talosService *talos.Service
	var kubeClient *kube.Client
	var helmClient *helm.Client

	for _, step := range []struct {
		name string
		run  func(context.Context) error
	}{
		{"generate Talos config", func(ctx context.Context) error {
			svc, err := b.phaseGenerateConfig(ctx)
			if err != nil {
				return err
			}
			talosService = svc
			return nil
		}},
		{"apply control plane config", func(ctx context.Context) error {
			return b.phaseApplyControlPlane(ctx, talosService)
		}},
		{"apply worker config", func(ctx context.Context) error {
			return b.phaseApplyWorker(ctx, talosService)
		}},
		{"bootstrap etcd", func(ctx context.Context) error {
			return b.phaseBootstrapEtcd(ctx, talosService)
		}},
		{"reboot bootstrapped nodes", func(ctx context.Context) error {
			return b.phaseRebootBootstrapped(ctx, talosService)
		}},
		{"wait for kube API", b.phaseWaitKubeAPI},
		{"fetch kubeconfig", func(ctx context.Context) error {
			kc, hc, err := b.phaseKubeconfig(ctx, talosService)
			if err != nil {
				return err
			}
			kubeClient = kc
			helmClient = hc
			return nil
		}},
		{"clean up Flannel", func(ctx context.Context) error {
			return b.phaseCleanupFlannel(ctx, kubeClient)
		}},
		{"clean up kube-proxy", func(ctx context.Context) error {
			return b.phaseCleanupKubeProxy(ctx, kubeClient)
		}},
		{"install Cilium", func(ctx context.Context) error {
			return b.phaseCilium(ctx, kubeClient, helmClient)
		}},
		{"install Gateway API CRDs", func(ctx context.Context) error {
			return b.phaseGatewayCRDs(ctx, kubeClient, helmClient)
		}},
		{"configure SOPS", func(ctx context.Context) error {
			return b.phaseSOPS(ctx, kubeClient)
		}},
		{"install Flux", func(ctx context.Context) error {
			return b.phaseFlux(ctx, kubeClient)
		}},
		{"apply post-bootstrap manifests", func(ctx context.Context) error {
			return b.phasePostManifests(ctx, kubeClient)
		}},
		{"restart Cilium for Gateway API", func(ctx context.Context) error {
			return b.phaseRestartCilium(ctx, kubeClient)
		}},
		{"cluster health check", func(ctx context.Context) error {
			return b.phaseHealth(ctx, talosService)
		}},
	} {
		log.Info().Str("phase", step.name).Msg("starting phase")
		if err := step.run(ctx); err != nil {
			return fmt.Errorf("%s: %w", step.name, err)
		}
		if b.skipClusterConfiguration && step.name == "reboot bootstrapped nodes" {
			log.Info().Msg("--skip-cluster-configuration set; stopping after Talos bootstrap")
			return nil
		}
	}
	return nil
}

func validateBootstrapNodes(bootstrapNodes map[string]string, cpNodes, workerNodes []string) (bool, error) {
	known := map[string]struct{}{}
	for _, n := range cpNodes {
		known[n] = struct{}{}
	}
	for _, n := range workerNodes {
		known[n] = struct{}{}
	}
	for n := range bootstrapNodes {
		if _, ok := known[n]; !ok {
			return false, fmt.Errorf("unknown node in --bootstrap: %s", n)
		}
	}
	return len(bootstrapNodes) > 0 && len(bootstrapNodes) == len(known), nil
}

func (b *Bootstrap) fqdn(parts ...string) string {
	return b.cfg.Cluster.FQDN(parts...)
}

func (b *Bootstrap) endpointFor(node string) string {
	if ep, ok := b.bootstrapNodes[node]; ok && ep != "" {
		return ep
	}
	return b.fqdn(node)
}

func (b *Bootstrap) isBootstrapping(node string) bool {
	_, ok := b.bootstrapNodes[node]
	return ok
}

func (b *Bootstrap) controlPlaneFQDNs() []string {
	return util.Map(b.cpNodes, func(node string) string {
		return b.fqdn(node)
	})
}

func (b *Bootstrap) workerFQDNs() []string {
	return util.Map(b.workerNodes, func(node string) string {
		return b.fqdn(node)
	})
}

func (b *Bootstrap) ciliumOptions() cilium.Options {
	return b.ciliumOpts
}

func (b *Bootstrap) waitStageFor(ctx context.Context, talosService *talos.Service, node string) error {
	if b.isBootstrapping(node) {
		ep := b.endpointFor(node)
		log.Info().
			Str("node", node).
			Str("stage", talos.StageMaintenance.String()).
			Msg("waiting for node stage")
		return talosService.WaitStage(ctx, ep, talos.StageMaintenance, talos.StageOpts{
			Endpoint: ep,
			Insecure: true,
		})
	}
	target := b.fqdn(node)
	log.Info().
		Str("node", node).
		Str("stage", talos.StageRunning.String()).
		Msg("waiting for node stage")
	return talosService.WaitStage(ctx, target, talos.StageRunning, talos.StageOpts{})
}
