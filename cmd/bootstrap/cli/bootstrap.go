// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/twelho/talos-bootstrap/internal/bootstrap"
	"github.com/twelho/talos-bootstrap/internal/config"
)

func bootstrapCmd() *cobra.Command {
	var (
		overrides nodeOverrides
		skip      bool
	)
	cmd := &cobra.Command{
		Use:   "bootstrap <config-file>",
		Short: "Bootstrap a Talos cluster end-to-end from a YAML cluster config",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cfg, dir, err := config.Load(args[0])
			if err != nil {
				return err
			}
			p, err := bootstrap.New(bootstrap.Options{
				Config:                   cfg,
				Dir:                      dir,
				BootstrapNodes:           overrides.Nodes,
				SkipClusterConfiguration: skip,
			})
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return p.Run(ctx)
		},
	}
	cmd.Flags().VarP(&overrides, "bootstrap", "b",
		"node to bootstrap, with optional =endpoint override (repeatable; comma-separated entries also accepted)")
	cmd.Flags().BoolVarP(&skip, "skip-cluster-configuration", "s", false,
		"bootstrap/configure Talos only; skip the Kubernetes cluster configuration steps")
	return cmd
}
