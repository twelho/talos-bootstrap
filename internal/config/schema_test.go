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
	if doc["additionalProperties"] != false {
		t.Errorf("top-level schema must close additionalProperties, got %v", doc["additionalProperties"])
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
	// dive,unique on the map field should propagate uniqueItems onto the
	// value schema (the per-node patch array), matching what the validator
	// enforces at runtime.
	ap := nodes["additionalProperties"].(map[string]any)
	if got := ap["uniqueItems"]; got != true {
		t.Errorf("controlplane.nodes value uniqueItems: got %v", got)
	}
	if got := ap["type"]; got != "array" {
		t.Errorf("controlplane.nodes value type: got %v", got)
	}

	// Cluster.Patches is omitempty,unique,dive,required: array uniqueItems
	// propagates, but the per-item required does not (no JSON Schema
	// equivalent for required-non-empty items).
	patches := cluster["properties"].(map[string]any)["patches"].(map[string]any)
	if got := patches["uniqueItems"]; got != true {
		t.Errorf("cluster.patches uniqueItems: got %v", got)
	}

	// native-routing has a required CIDR-formatted field.
	nr := cluster["properties"].(map[string]any)["cilium"].(map[string]any)["properties"].(map[string]any)["native-routing"].(map[string]any)
	nrRequired := nr["required"].([]any)
	if len(nrRequired) != 1 || nrRequired[0] != "ipv4-cidr" {
		t.Errorf("native-routing.required: got %v", nrRequired)
	}
	cidrField := nr["properties"].(map[string]any)["ipv4-cidr"].(map[string]any)
	if got := cidrField["format"]; got != "cidr" {
		t.Errorf("native-routing.ipv4-cidr format: got %v", got)
	}

	// sops uses required_without (cross-field), which intentionally does not
	// map to JSON Schema; no "required" array should appear on the sops
	// object.
	sops := cluster["properties"].(map[string]any)["sops"].(map[string]any)
	if _, ok := sops["required"]; ok {
		t.Errorf("sops should not have a JSON Schema required list (required_without is cross-field)")
	}
}
