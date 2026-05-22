// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package cli wires the cobra command tree. Root carries no behaviour of its
// own; each subcommand owns its flags and Run function so adding a new top-level
// operation is a one-file change.
package cli

import (
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func Root() *cobra.Command {
	var verbose bool
	root := &cobra.Command{
		Use:           "talos-bootstrap",
		Short:         "Bootstrap and configure a provisioned Talos Linux cluster",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			if verbose {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}
		},
	}
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"emit debug-level logs (retry loops, helm SDK, etc.)")
	root.AddCommand(bootstrapCmd())
	root.AddCommand(ciliumCmd())
	root.AddCommand(factsCmd())
	root.AddCommand(schemaCmd())
	return root
}
