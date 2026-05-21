// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package cli wires the cobra command tree. Root carries no behaviour of its
// own; each subcommand owns its flags and Run function so adding a new top-level
// operation is a one-file change.
package cli

import "github.com/spf13/cobra"

func Root() *cobra.Command {
	root := &cobra.Command{
		Use:           "talos-bootstrap",
		Short:         "Bootstrap and configure a provisioned Talos Linux cluster",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(bootstrapCmd())
	root.AddCommand(ciliumCmd())
	root.AddCommand(schemaCmd())
	return root
}
