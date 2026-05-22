// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package bootstrap

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	talosversion "github.com/siderolabs/talos/pkg/machinery/version"

	"github.com/twelho/talos-bootstrap/internal/talos"
)

// imageHasTag reports whether a container image reference already carries an
// explicit tag. Only the final path segment can contain the tag separator;
// a colon earlier in the reference belongs to a registry port (e.g.
// localhost:5000/talos/installer).
func imageHasTag(image string) bool {
	last := image
	if i := strings.LastIndex(image, "/"); i >= 0 {
		last = image[i+1:]
	}
	return strings.Contains(last, ":")
}

func (p *Pipeline) phaseGenerateConfig(_ context.Context) error {
	cluster := p.cfg.Cluster
	endpoints := p.controlPlaneFQDNs()
	if p.cfg.ControlPlane.RecordAsEndpoint {
		endpoints = []string{p.fqdn(p.cfg.ControlPlane.Record)}
	}

	image := strings.TrimRight(cluster.Image, ":")
	if image != "" && !imageHasTag(image) {
		// Pin to the machinery library version so installer image upgrades
		// follow the talos-bootstrap binary.
		image = image + ":" + talosversion.Tag
	}

	endpoint := (&url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(p.fqdn(p.cfg.ControlPlane.Record), strconv.Itoa(apiServerPort)),
	}).String()

	res, err := talos.Generate(talos.GenerateRequest{
		ClusterName:  cluster.Name,
		Endpoint:     endpoint,
		SecretsPath:  p.resolvePath(cluster.Secrets),
		InstallImage: image,
		Patches:      p.resolvePatches(cluster.Patches),
		Endpoints:    endpoints,
		DefaultNode:  endpoints[0],
		OutputDir:    p.dir,
	})
	if err != nil {
		return err
	}
	if err := talos.MergeTalosconfig(res.TalosconfigFile, ""); err != nil {
		return err
	}
	svc, err := talos.NewService("")
	if err != nil {
		return err
	}
	p.talosService = svc
	return nil
}

func (p *Pipeline) phaseApplyControlPlane(ctx context.Context) error {
	for _, node := range p.cpNodes {
		if err := p.waitStageForApply(ctx, node); err != nil {
			return err
		}
	}
	return p.applyConfigToSet(ctx, p.cpNodes, "controlplane.yaml",
		p.cfg.ControlPlane.Patches, p.cfg.ControlPlane.Nodes)
}

func (p *Pipeline) phaseApplyWorker(ctx context.Context) error {
	for _, node := range p.workerNodes {
		if err := p.waitStageForApply(ctx, node); err != nil {
			return err
		}
	}
	return p.applyConfigToSet(ctx, p.workerNodes, "worker.yaml",
		p.cfg.Worker.Patches, p.cfg.Worker.Nodes)
}

func (p *Pipeline) applyConfigToSet(
	ctx context.Context,
	nodes []string,
	file string,
	globalPatches []string,
	nodePatches map[string][]string,
) error {
	data, err := os.ReadFile(p.resolvePath(file))
	if err != nil {
		return fmt.Errorf("read %s: %w", file, err)
	}
	for _, node := range nodes {
		patches := p.resolvePatches(slices.Concat(globalPatches, nodePatches[node]))
		opts := talos.ApplyOpts{Patches: patches}
		target := p.fqdn(node)
		if p.isBootstrapping(node) {
			opts.Insecure = true
			opts.ForceReboot = true
			opts.Endpoint = p.endpointFor(node)
			target = opts.Endpoint
		}
		if err := p.talosService.ApplyConfig(ctx, target, data, opts); err != nil {
			return err
		}
	}
	return nil
}

func (p *Pipeline) phaseBootstrapEtcd(ctx context.Context) error {
	if !p.bootstrapAll {
		log.Info().Msg("partial bootstrap; skipping etcd initialization (assuming an existing cluster)")
		return nil
	}
	// Bootstrap retries internally until the node accepts the call. While the
	// node is mid-reboot the TLS dial fails (Unavailable, transient), and the
	// stages between Rebooting and Running are not linearly ordered so a
	// WaitStage gate would only introduce a race without adding safety.
	return p.talosService.Bootstrap(ctx, p.fqdn(p.cpNodes[0]), bootstrapRetry)
}

func (p *Pipeline) phaseRebootBootstrapped(ctx context.Context) error {
	if len(p.bootstrapNodes) == 0 {
		return nil
	}
	var toReboot []string
	for _, n := range p.cpNodes {
		if p.isBootstrapping(n) {
			toReboot = append(toReboot, n)
		}
	}
	for _, n := range p.workerNodes {
		if p.isBootstrapping(n) {
			toReboot = append(toReboot, n)
		}
	}
	for _, n := range toReboot {
		if err := p.waitStageRunning(ctx, n); err != nil {
			return err
		}
	}
	if err := p.talosService.Reboot(ctx, p.fqdns(toReboot)); err != nil {
		return err
	}
	// Allow time for the nodes to enter the rebooting stage before polling.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(postRebootSettle):
	}
	for _, n := range toReboot {
		if err := p.waitStageRunning(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

func (p *Pipeline) phaseHealth(ctx context.Context) error {
	// The Talos health RPC takes its own deadline (WaitTimeout) and propagates
	// it as the stream's gRPC deadline, so we do not need a second
	// context.WithTimeout wrapping it.
	return p.talosService.Health(ctx, talos.HealthRequest{
		ControlPlanes: p.controlPlaneFQDNs(),
		Workers:       p.workerFQDNs(),
		WaitTimeout:   healthTimeout,
	}, func(msg string) { log.Info().Msg(msg) })
}
