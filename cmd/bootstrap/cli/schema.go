// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/twelho/talos-bootstrap/internal/config"
)

func schemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Print the talos-bootstrap configuration JSON Schema",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			data, err := config.SchemaJSON()
			if err != nil {
				return fmt.Errorf("render schema: %w", err)
			}
			_, err = os.Stdout.Write(data)
			return err
		},
	}
}
