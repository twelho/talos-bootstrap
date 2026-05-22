// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/twelho/talos-bootstrap/internal/config"
	"github.com/twelho/talos-bootstrap/internal/facts"
)

// factsCmd emits the stable JSON facts document downstream GitOps repos
// template against. The contract is versioned via facts.SchemaVersion and the
// shape is pinned by the golden file test in internal/facts.
func factsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "facts <config-file>",
		Short: "Print the cluster facts JSON document for downstream consumers",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cfg, _, err := config.Load(args[0])
			if err != nil {
				return err
			}
			data, err := json.MarshalIndent(facts.From(cfg), "", "  ")
			if err != nil {
				return fmt.Errorf("marshal facts: %w", err)
			}
			if _, err := os.Stdout.Write(data); err != nil {
				return err
			}
			_, err = os.Stdout.Write([]byte{'\n'})
			return err
		},
	}
}
