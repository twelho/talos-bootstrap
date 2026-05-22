// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/twelho/talos-bootstrap/internal/cilium"
	"github.com/twelho/talos-bootstrap/internal/config"
)

// ciliumCmd exposes the typed Cilium options as a subcommand tree. `values`
// emits the rendered Helm values.yaml for the cluster's Cilium block, which
// is the contract relied on by external tooling that wants to consume the
// same source of truth without re-deriving it.
func ciliumCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cilium",
		Short: "Inspect or render the Cilium configuration",
	}
	cmd.AddCommand(ciliumValuesCmd())
	return cmd
}

func ciliumValuesCmd() *cobra.Command {
	agent := true
	cmd := &cobra.Command{
		Use:   "values <config-file>",
		Short: "Render the Cilium Helm values.yaml that talos-bootstrap would install",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := config.Load(args[0])
			if err != nil {
				return err
			}
			opts := cilium.FromConfig(cfg.Cluster.Cilium, cilium.TopologyFromConfig(cfg))
			data, err := opts.ValuesYAML(agent)
			if err != nil {
				return fmt.Errorf("render values: %w", err)
			}
			_, err = os.Stdout.Write(data)
			return err
		},
	}
	cmd.Flags().BoolVar(&agent, "agent", true,
		"include the agent DaemonSet (set false to render the operator-only variant used for the pre-CNI manifests phase)")
	return cmd
}
