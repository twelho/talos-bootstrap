// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package config

import (
	"encoding/json"
	"testing"
)

func TestSchemaJSON(t *testing.T) {
	data, err := SchemaJSON()
	if err != nil {
		t.Fatalf("SchemaJSON: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if got := doc["$schema"]; got != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("$schema: got %v", got)
	}

	props := doc["properties"].(map[string]any)
	cluster := props["cluster"].(map[string]any)
	required := cluster["required"].([]any)
	if len(required) != 2 || required[0] != "name" || required[1] != "secrets" {
		t.Fatalf("cluster required fields: got %v", required)
	}

	cp := props["controlplane"].(map[string]any)
	nodes := cp["properties"].(map[string]any)["nodes"].(map[string]any)
	if got := nodes["minProperties"]; got != float64(1) {
		t.Fatalf("controlplane.nodes minProperties: got %v", got)
	}
}
