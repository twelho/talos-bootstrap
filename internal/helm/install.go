// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package helm wraps the helm v3 SDK with the install/upgrade flow needed by
// talos-bootstrap. The values map is taken as-is (no --set string mangling),
// which is the entire point of having a typed cilium.Options upstream.
package helm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/repo"
	"helm.sh/helm/v3/pkg/storage/driver"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// Client wires up a helm action.Configuration backed by a kubeconfig file
// and a transient settings instance. Construct one per cluster install and
// reuse it across releases in the same run.
type Client struct {
	settings *cli.EnvSettings
	cfg      *action.Configuration
}

// New initialises the helm runtime. kubeconfig may be empty to fall back to
// helm's standard precedence; namespace is the operations namespace for the
// release storage backend.
func New(kubeconfig, namespace string) (*Client, error) {
	settings := cli.New()
	if kubeconfig != "" {
		settings.KubeConfig = kubeconfig
	}

	flags := genericclioptions.NewConfigFlags(true)
	if kubeconfig != "" {
		flags.KubeConfig = &kubeconfig
	}
	if namespace != "" {
		flags.Namespace = &namespace
	}

	cfg := new(action.Configuration)
	if err := cfg.Init(flags, namespace, os.Getenv("HELM_DRIVER"), debugLog); err != nil {
		return nil, fmt.Errorf("init helm: %w", err)
	}
	return &Client{settings: settings, cfg: cfg}, nil
}

// AddRepo adds (or updates) a chart repository entry, then downloads its
// index file. This replaces `helm repo add <name> <url>`.
func (c *Client) AddRepo(name, url string) error {
	entry := &repo.Entry{Name: name, URL: url}
	r, err := repo.NewChartRepository(entry, getter.All(c.settings))
	if err != nil {
		return fmt.Errorf("init repo %q: %w", name, err)
	}
	r.CachePath = c.settings.RepositoryCache
	if _, err := r.DownloadIndexFile(); err != nil {
		return fmt.Errorf("download index for %q (%s): %w", name, url, err)
	}
	return nil
}

// UpgradeOrInstall mirrors `helm upgrade --install`. It creates the release
// if missing or upgrades it in place. Wait controls whether the call blocks
// until all created resources are Ready.
type UpgradeOrInstallRequest struct {
	ReleaseName string
	ChartRef    string // e.g. "cilium/cilium"
	Namespace   string
	Version     string // empty means latest
	Values      map[string]any
	Wait        bool
}

func (c *Client) UpgradeOrInstall(ctx context.Context, req UpgradeOrInstallRequest) (*release.Release, error) {
	hist := action.NewHistory(c.cfg)
	hist.Max = 1
	_, err := hist.Run(req.ReleaseName)
	switch {
	case errors.Is(err, driver.ErrReleaseNotFound):
		return c.install(ctx, req)
	case err != nil:
		return nil, fmt.Errorf("read release history for %s: %w", req.ReleaseName, err)
	default:
		return c.upgrade(ctx, req)
	}
}

func (c *Client) install(ctx context.Context, req UpgradeOrInstallRequest) (*release.Release, error) {
	inst := action.NewInstall(c.cfg)
	inst.ReleaseName = req.ReleaseName
	inst.Namespace = req.Namespace
	inst.CreateNamespace = true
	inst.Wait = req.Wait
	inst.Version = req.Version

	chart, err := c.loadChart(inst.ChartPathOptions, req.ChartRef, req.Version)
	if err != nil {
		return nil, err
	}
	log.Info().Str("release", req.ReleaseName).Str("chart", req.ChartRef).
		Str("namespace", req.Namespace).Msg("installing helm release")
	rel, err := inst.RunWithContext(ctx, chart, req.Values)
	if err != nil {
		return nil, fmt.Errorf("install %s: %w", req.ReleaseName, err)
	}
	return rel, nil
}

func (c *Client) upgrade(ctx context.Context, req UpgradeOrInstallRequest) (*release.Release, error) {
	up := action.NewUpgrade(c.cfg)
	up.Namespace = req.Namespace
	up.Wait = req.Wait
	up.Version = req.Version
	// Install=true lets helm self-heal if the release vanished between our
	// history probe and the upgrade RPC (rare TOCTOU, but cheap to cover).
	up.Install = true

	chart, err := c.loadChart(up.ChartPathOptions, req.ChartRef, req.Version)
	if err != nil {
		return nil, err
	}
	log.Info().Str("release", req.ReleaseName).Str("chart", req.ChartRef).
		Str("namespace", req.Namespace).Msg("upgrading helm release")
	rel, err := up.RunWithContext(ctx, req.ReleaseName, chart, req.Values)
	if err != nil {
		return nil, fmt.Errorf("upgrade %s: %w", req.ReleaseName, err)
	}
	return rel, nil
}

func (c *Client) loadChart(opts action.ChartPathOptions, ref, version string) (*chart.Chart, error) {
	opts.Version = version
	path, err := opts.LocateChart(ref, c.settings)
	if err != nil {
		return nil, fmt.Errorf("locate chart %s: %w", ref, err)
	}
	chart, err := loader.Load(path)
	if err != nil {
		return nil, fmt.Errorf("load chart %s from %q: %w", ref, path, err)
	}
	return chart, nil
}

// LatestVersion looks up the latest stable version of a chart in a configured
// repository. Replaces `helm search repo <chart> -o json` parsing.
func (c *Client) LatestVersion(repoName, chartName string) (string, error) {
	idx, err := repo.LoadIndexFile(filepath.Join(c.settings.RepositoryCache, repoName+"-index.yaml"))
	if err != nil {
		return "", fmt.Errorf("load index for %q: %w", repoName, err)
	}
	cv, err := idx.Get(chartName, "")
	if err != nil {
		return "", fmt.Errorf("lookup chart %q: %w", chartName, err)
	}
	return cv.Version, nil
}

func debugLog(format string, v ...any) {
	log.Debug().Msgf("helm: "+format, v...)
}
