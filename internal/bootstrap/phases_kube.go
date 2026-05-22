// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package bootstrap

import (
	"context"
	"time"

	"github.com/twelho/talos-bootstrap/internal/helm"
	"github.com/twelho/talos-bootstrap/internal/kube"
)

func (p *Pipeline) phaseWaitKubeAPI(ctx context.Context) error {
	// Reboot windows: brief wait so the API server actually goes down before
	// we conclude it is back up.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(apiServerSettle):
	}
	return kube.WaitAPIServer(ctx, p.fqdn(p.cfg.ControlPlane.Record), apiServerPort)
}

func (p *Pipeline) phaseKubeconfig(ctx context.Context) error {
	data, err := p.talosService.Kubeconfig(ctx, p.fqdn(p.cpNodes[0]))
	if err != nil {
		return err
	}
	if err := kube.WriteKubeconfig("", data); err != nil {
		return err
	}
	c, err := kube.NewFromKubeconfig("")
	if err != nil {
		return err
	}
	h, err := helm.New(kube.DefaultKubeconfigPath(), systemNamespace)
	if err != nil {
		return err
	}
	p.kubeClient = c
	p.helmClient = h
	return nil
}

// The two cleanup phases briefly leave the cluster without a CNI and
// kube-proxy; phaseCilium restores connectivity in the next step.
func (p *Pipeline) phaseCleanupFlannel(ctx context.Context) error {
	return p.kubeClient.PurgeBySelector(ctx, systemNamespace, "k8s-app=flannel")
}

func (p *Pipeline) phaseCleanupKubeProxy(ctx context.Context) error {
	return p.kubeClient.PurgeByName(ctx, systemNamespace, "kube-proxy")
}
