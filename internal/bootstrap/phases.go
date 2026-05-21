// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package bootstrap

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	talosversion "github.com/siderolabs/talos/pkg/machinery/version"

	"github.com/twelho/talos-bootstrap/internal/flux"
	"github.com/twelho/talos-bootstrap/internal/gateway"
	"github.com/twelho/talos-bootstrap/internal/helm"
	"github.com/twelho/talos-bootstrap/internal/kube"
	"github.com/twelho/talos-bootstrap/internal/manifests"
	"github.com/twelho/talos-bootstrap/internal/sops"
	"github.com/twelho/talos-bootstrap/internal/talos"
)

func (b *Bootstrap) phaseGenerateConfig(ctx context.Context) (*talos.Service, error) {
	cluster := b.cfg.Cluster
	endpoints := b.controlPlaneFQDNs()
	if b.cfg.ControlPlane.RecordAsEndpoint {
		endpoints = []string{b.fqdn(b.cfg.ControlPlane.Record)}
	}

	image := cluster.Image
	if image != "" && !strings.Contains(image, ":") {
		// No tag set: pin to the machinery library version so installer image
		// upgrades follow the talos-bootstrap binary.
		image = image + ":" + talosVersion()
	}

	endpoint := fmt.Sprintf("https://%s:%d", b.fqdn(b.cfg.ControlPlane.Record), apiServerPort)

	res, err := talos.Generate(talos.GenerateRequest{
		ClusterName:  cluster.Name,
		Endpoint:     endpoint,
		SecretsPath:  cluster.Secrets,
		InstallImage: image,
		Patches:      cluster.Patches,
		Endpoints:    endpoints,
		DefaultNode:  endpoints[0],
		OutputDir:    ".",
	})
	if err != nil {
		return nil, err
	}
	if err := talos.MergeTalosconfig(res.TalosconfigFile, ""); err != nil {
		return nil, err
	}
	svc, err := talos.NewService("")
	if err != nil {
		return nil, err
	}
	return svc, nil
}

func (b *Bootstrap) phaseApplyControlPlane(ctx context.Context, talosService *talos.Service) error {
	for _, node := range b.cpNodes {
		if err := b.waitStageFor(ctx, talosService, node); err != nil {
			return err
		}
	}
	return b.applyConfigToSet(ctx, talosService, b.cpNodes, "controlplane.yaml",
		b.cfg.ControlPlane.Patches, b.cfg.ControlPlane.Nodes)
}

func (b *Bootstrap) phaseApplyWorker(ctx context.Context, talosService *talos.Service) error {
	for _, node := range b.workerNodes {
		if err := b.waitStageFor(ctx, talosService, node); err != nil {
			return err
		}
	}
	return b.applyConfigToSet(ctx, talosService, b.workerNodes, "worker.yaml",
		b.cfg.Worker.Patches, b.cfg.Worker.Nodes)
}

func (b *Bootstrap) applyConfigToSet(
	ctx context.Context,
	talosService *talos.Service,
	nodes []string,
	file string,
	globalPatches []string,
	nodePatches map[string][]string,
) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read %s: %w", file, err)
	}
	for _, node := range nodes {
		patches := append([]string{}, globalPatches...)
		patches = append(patches, nodePatches[node]...)
		opts := talos.ApplyOpts{Patches: patches}
		target := b.fqdn(node)
		if b.isBootstrapping(node) {
			opts.Insecure = true
			opts.ForceReboot = true
			opts.Endpoint = b.endpointFor(node)
			target = opts.Endpoint
		}
		if err := talosService.ApplyConfig(ctx, target, data, opts); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bootstrap) phaseBootstrapEtcd(ctx context.Context, talosService *talos.Service) error {
	if !b.bootstrapAll {
		return nil
	}
	first := b.cpNodes[0]
	if err := talosService.WaitStage(ctx, b.endpointFor(first), talos.StageBooting, talos.StageOpts{
		Endpoint: b.endpointFor(first),
		Insecure: true,
	}); err != nil {
		return err
	}
	return talosService.Bootstrap(ctx, b.fqdn(first), b.bootstrapRetry)
}

func (b *Bootstrap) phaseRebootBootstrapped(ctx context.Context, talosService *talos.Service) error {
	if len(b.bootstrapNodes) == 0 {
		return nil
	}
	for node := range b.bootstrapNodes {
		if !slices.Contains(b.cpNodes, node) {
			continue
		}
		if err := talosService.WaitStage(ctx, b.fqdn(node), talos.StageRunning, talos.StageOpts{}); err != nil {
			return err
		}
	}
	for node := range b.bootstrapNodes {
		if !slices.Contains(b.workerNodes, node) {
			continue
		}
		if err := talosService.WaitStage(ctx, b.fqdn(node), talos.StageRunning, talos.StageOpts{}); err != nil {
			return err
		}
	}
	nodes := make([]string, 0, len(b.bootstrapNodes))
	for n := range b.bootstrapNodes {
		nodes = append(nodes, b.fqdn(n))
	}
	if err := talosService.Reboot(ctx, nodes); err != nil {
		return err
	}
	// Allow time for the nodes to enter the rebooting stage before polling.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
	}
	for n := range b.bootstrapNodes {
		if err := talosService.WaitStage(ctx, b.fqdn(n), talos.StageRunning, talos.StageOpts{}); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bootstrap) phaseWaitKubeAPI(ctx context.Context) error {
	if b.skipClusterConfiguration {
		return nil
	}
	// Reboot windows: brief wait so the API server actually goes down before
	// we conclude it is back up.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
	}
	return kube.WaitAPIServer(ctx, b.fqdn(b.cfg.ControlPlane.Record), apiServerPort)
}

func (b *Bootstrap) phaseKubeconfig(ctx context.Context, talosService *talos.Service) (*kube.Client, *helm.Client, error) {
	if b.skipClusterConfiguration {
		return nil, nil, nil
	}
	data, err := talosService.Kubeconfig(ctx, b.fqdn(b.cpNodes[0]))
	if err != nil {
		return nil, nil, err
	}
	if err := kube.WriteKubeconfig("", data); err != nil {
		return nil, nil, err
	}
	c, err := kube.NewFromKubeconfig("")
	if err != nil {
		return nil, nil, err
	}
	h, err := helm.New(kube.DefaultKubeconfigPath(), "kube-system")
	if err != nil {
		return nil, nil, err
	}
	return c, h, nil
}

func (b *Bootstrap) phaseCleanupFlannel(ctx context.Context, kubeClient *kube.Client) error {
	if b.skipClusterConfiguration {
		return nil
	}
	return kubeClient.PurgeBySelector(ctx, "kube-system", "k8s-app=flannel")
}

func (b *Bootstrap) phaseCleanupKubeProxy(ctx context.Context, kubeClient *kube.Client) error {
	if b.skipClusterConfiguration {
		return nil
	}
	return kubeClient.PurgeByName(ctx, "kube-system", "kube-proxy")
}

func (b *Bootstrap) phaseCilium(ctx context.Context, kubeClient *kube.Client, helmClient *helm.Client) error {
	if b.skipClusterConfiguration {
		return nil
	}
	if err := helmClient.AddRepo(ciliumRepoName, ciliumRepoURL); err != nil {
		return err
	}
	opts := b.ciliumOptions()

	if dir := b.cfg.Cluster.ManifestsPre; dir != "" {
		exists, err := kubeClient.CRDExists(ctx, "ciliumnetworkpolicies.cilium.io")
		if err != nil {
			return err
		}
		if !exists {
			if err := b.installCilium(ctx, helmClient, opts.Values(false)); err != nil {
				return err
			}
			if err := waitForCRD(ctx, kubeClient, "ciliumnetworkpolicies.cilium.io"); err != nil {
				return err
			}
		}
		objs, err := manifests.Render(dir)
		if err != nil {
			return err
		}
		if err := manifests.Apply(ctx, kubeClient, objs); err != nil {
			return err
		}
	}

	return b.installCilium(ctx, helmClient, opts.Values(true))
}

func (b *Bootstrap) installCilium(ctx context.Context, helmClient *helm.Client, values map[string]any) error {
	_, err := helmClient.UpgradeOrInstall(ctx, helm.UpgradeOrInstallRequest{
		ReleaseName: "cilium",
		ChartRef:    ciliumChart,
		Namespace:   "kube-system",
		Values:      values,
		Wait:        true,
	})
	return err
}

func (b *Bootstrap) phaseGatewayCRDs(ctx context.Context, kubeClient *kube.Client, helmClient *helm.Client) error {
	if b.skipClusterConfiguration {
		return nil
	}
	opts := b.ciliumOptions()
	if !opts.GatewayAPIEnabled() {
		return nil
	}
	cv, err := helmClient.LatestVersion(ciliumRepoName, "cilium")
	if err != nil {
		return err
	}
	gwVer, err := gateway.ResolveVersion(ctx, cv)
	if err != nil {
		return err
	}
	log.Info().Str("version", gwVer).Msg("installing Gateway API CRDs")
	if err := gateway.InstallCRDs(ctx, kubeClient, gwVer); err != nil {
		return err
	}
	log.Info().Msg("waiting for Cilium Gateway API CRDs")
	return waitForCRD(ctx, kubeClient, "ciliumgatewayclassconfigs.cilium.io")
}

func (b *Bootstrap) phaseSOPS(ctx context.Context, kubeClient *kube.Client) error {
	if b.skipClusterConfiguration {
		return nil
	}
	s := b.cfg.Cluster.SOPS
	if s == nil {
		return nil
	}
	if s.GPG != "" {
		if err := sops.EnsureGPG(ctx, kubeClient, s.GPG); err != nil {
			return err
		}
	}
	if s.Age != "" {
		if err := sops.EnsureAge(ctx, kubeClient, s.Age); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bootstrap) phaseFlux(ctx context.Context, kubeClient *kube.Client) error {
	if b.skipClusterConfiguration {
		return nil
	}
	if b.cfg.Cluster.Flux == nil {
		return nil
	}
	return flux.Apply(ctx, kubeClient, b.cfg.Cluster.Flux)
}

func (b *Bootstrap) phasePostManifests(ctx context.Context, kubeClient *kube.Client) error {
	if b.skipClusterConfiguration {
		return nil
	}
	dir := b.cfg.Cluster.Manifests
	if dir == "" {
		return nil
	}
	objs, err := manifests.Render(dir)
	if err != nil {
		return err
	}
	return manifests.Apply(ctx, kubeClient, objs)
}

func (b *Bootstrap) phaseRestartCilium(ctx context.Context, kubeClient *kube.Client) error {
	if b.skipClusterConfiguration {
		return nil
	}
	if !b.ciliumOptions().GatewayAPIEnabled() {
		return nil
	}
	if err := kubeClient.RolloutRestart(ctx, "deployment", "kube-system", "cilium-operator"); err != nil {
		return err
	}
	return kubeClient.RolloutRestart(ctx, "daemonset", "kube-system", "cilium")
}

func (b *Bootstrap) phaseHealth(ctx context.Context, talosService *talos.Service) error {
	if b.skipClusterConfiguration {
		return nil
	}
	hctx, cancel := context.WithTimeout(ctx, b.healthTimeout)
	defer cancel()
	return talosService.Health(hctx, talos.HealthRequest{
		ControlPlanes: b.controlPlaneFQDNs(),
		Workers:       b.workerFQDNs(),
		WaitTimeout:   b.healthTimeout,
	}, func(msg string) { log.Info().Msg(msg) })
}

func waitForCRD(ctx context.Context, c *kube.Client, name string) error {
	for {
		ok, err := c.CRDExists(ctx, name)
		if ok {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// talosVersion is the upstream-embedded version tag of the Talos machinery
// library this binary was compiled against. Pinning installer-image tags to
// the machinery version (not the binary's own VCS version) keeps the running
// nodes on a release that this tool actually understands.
func talosVersion() string {
	return talosversion.Tag
}
