// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package bootstrap

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/twelho/talos-bootstrap/internal/flux"
	"github.com/twelho/talos-bootstrap/internal/gateway"
	"github.com/twelho/talos-bootstrap/internal/helm"
	"github.com/twelho/talos-bootstrap/internal/manifests"
	"github.com/twelho/talos-bootstrap/internal/monitoring"
	"github.com/twelho/talos-bootstrap/internal/sops"
)

// needsServiceMonitor reports whether the cluster has opted into Cilium's
// ServiceMonitor / PodMonitor emission via either the top-level metrics block
// or the Hubble metrics block. When neither is set, the prometheus-operator
// CRDs are not required and the monitoring phase is skipped.
func (p *Pipeline) needsServiceMonitor() bool {
	c := p.cfg.Cluster.Cilium
	if c == nil {
		return false
	}
	if c.Metrics != nil && c.Metrics.ServiceMonitor {
		return true
	}
	if c.Hubble != nil && c.Hubble.Metrics != nil && c.Hubble.Metrics.ServiceMonitor {
		return true
	}
	return false
}

// phaseMonitoringCRDs installs the prometheus-operator CRDs Cilium's chart
// validate.yaml requires when ServiceMonitor / PodMonitor emission is on. It
// must run before phaseCilium so even the operator-only pre-CNI install path
// finds the CRDs at chart render time.
func (p *Pipeline) phaseMonitoringCRDs(ctx context.Context) error {
	if !p.needsServiceMonitor() {
		return nil
	}
	log.Info().Str("version", monitoring.Version).Msg("installing prometheus-operator CRDs")
	if err := monitoring.InstallCRDs(ctx, p.kubeClient); err != nil {
		return err
	}
	for _, name := range monitoring.CRDs {
		if err := p.kubeClient.WaitCRDEstablished(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

func (p *Pipeline) phaseCilium(ctx context.Context) error {
	if err := p.helmClient.AddRepo(ciliumRepoName, ciliumRepoURL); err != nil {
		return err
	}
	opts := p.ciliumOpts

	if dir := p.cfg.Cluster.ManifestsPre; dir != "" {
		exists, err := p.kubeClient.CRDExists(ctx, "ciliumnetworkpolicies.cilium.io")
		if err != nil {
			return err
		}
		if !exists {
			if err := p.installCilium(ctx, opts.Values(false)); err != nil {
				return err
			}
			if err := p.kubeClient.WaitCRDEstablished(ctx, "ciliumnetworkpolicies.cilium.io"); err != nil {
				return err
			}
		}
		objs, err := manifests.Render(p.resolvePath(dir))
		if err != nil {
			return err
		}
		if err := manifests.Apply(ctx, p.kubeClient, objs); err != nil {
			return err
		}
	}

	return p.installCilium(ctx, opts.Values(true))
}

func (p *Pipeline) installCilium(ctx context.Context, values map[string]any) error {
	_, err := p.helmClient.UpgradeOrInstall(ctx, helm.UpgradeOrInstallRequest{
		ReleaseName: "cilium",
		ChartRef:    ciliumChart,
		Namespace:   systemNamespace,
		Values:      values,
		Wait:        true,
	})
	return err
}

func (p *Pipeline) phaseGatewayCRDs(ctx context.Context) error {
	if !p.ciliumOpts.GatewayAPIEnabled() {
		return nil
	}
	gwVer := p.ciliumOpts.GatewayAPIVersion()
	if gwVer == "" {
		cv, err := p.helmClient.LatestVersion(ciliumRepoName, "cilium")
		if err != nil {
			return err
		}
		gwVer, err = gateway.ResolveVersion(ctx, cv)
		if err != nil {
			return err
		}
	}
	log.Info().Str("version", gwVer).Msg("installing Gateway API CRDs")
	if err := gateway.InstallCRDs(ctx, p.kubeClient, gwVer); err != nil {
		return err
	}
	log.Info().Msg("waiting for Cilium Gateway API CRDs")
	return p.kubeClient.WaitCRDEstablished(ctx, "ciliumgatewayclassconfigs.cilium.io")
}

func (p *Pipeline) phaseSOPS(ctx context.Context) error {
	s := p.cfg.Cluster.SOPS
	if s == nil {
		return nil
	}
	if s.GPG != "" {
		if err := sops.EnsureGPG(ctx, p.kubeClient, s.GPG); err != nil {
			return err
		}
	}
	if s.Age != "" {
		if err := sops.EnsureAge(ctx, p.kubeClient, p.resolvePath(s.Age)); err != nil {
			return err
		}
	}
	return nil
}

func (p *Pipeline) phaseFlux(ctx context.Context) error {
	if p.cfg.Cluster.Flux == nil {
		return nil
	}
	return flux.Apply(ctx, p.kubeClient, p.cfg.Cluster.Flux)
}

func (p *Pipeline) phasePostManifests(ctx context.Context) error {
	dir := p.cfg.Cluster.Manifests
	if dir == "" {
		return nil
	}
	objs, err := manifests.Render(p.resolvePath(dir))
	if err != nil {
		return err
	}
	return manifests.Apply(ctx, p.kubeClient, objs)
}

func (p *Pipeline) phaseRestartCilium(ctx context.Context) error {
	if !p.ciliumOpts.GatewayAPIEnabled() {
		return nil
	}
	if err := p.kubeClient.RolloutRestartDeployment(ctx, systemNamespace, "cilium-operator"); err != nil {
		return err
	}
	return p.kubeClient.RolloutRestartDaemonSet(ctx, systemNamespace, "cilium")
}
