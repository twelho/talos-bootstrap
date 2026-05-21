// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package config

import "encoding/json"

// SchemaJSON returns a JSON Schema document for talos-bootstrap YAML
// configuration files. YAML language servers consume JSON Schema for validation
// and completion, so the property names intentionally follow the yaml tags in
// types.go.
func SchemaJSON() ([]byte, error) {
	data, err := json.MarshalIndent(schema(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func schema() map[string]any {
	return object(map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$id":     "https://github.com/twelho/talos-bootstrap/schema/config.schema.json",
		"title":   "talos-bootstrap configuration",
		"required": []string{
			"cluster",
			"controlplane",
		},
		"properties": map[string]any{
			"cluster":      clusterSchema(),
			"controlplane": controlPlaneSchema(),
			"worker":       workerSchema(),
		},
	})
}

func clusterSchema() map[string]any {
	return object(map[string]any{
		"required": []string{
			"name",
			"secrets",
		},
		"properties": map[string]any{
			"name":          stringSchema(),
			"domain":        stringSchema(),
			"secrets":       stringSchema(),
			"cilium":        ciliumSchema(),
			"sops":          sopsSchema(),
			"flux":          fluxSchema(),
			"image":         stringSchema(),
			"patches":       stringList(true),
			"manifests-pre": stringSchema(),
			"manifests":     stringSchema(),
		},
	})
}

func ciliumSchema() map[string]any {
	return object(map[string]any{
		"properties": map[string]any{
			"metrics":        metricsSchema(),
			"hubble":         hubbleSchema(),
			"hardening":      hardeningSchema(),
			"gateway-api":    gatewayAPISchema(),
			"node-ipam":      enabledSchema(),
			"native-routing": nativeRoutingSchema(),
			"netkit":         boolSchema(),
			"bgp":            enabledSchema(),
			"masquerade":     masqueradeSchema(),
		},
	})
}

func metricsSchema() map[string]any {
	return object(map[string]any{
		"properties": map[string]any{
			"enabled":        boolSchema(),
			"servicemonitor": boolSchema(),
		},
	})
}

func hubbleSchema() map[string]any {
	return object(map[string]any{
		"properties": map[string]any{
			"enabled": boolSchema(),
			"metrics": metricsSchema(),
			"export": object(map[string]any{
				"required": []string{"path"},
				"properties": map[string]any{
					"enabled": boolSchema(),
					"path":    stringSchema(),
				},
			}),
		},
	})
}

func hardeningSchema() map[string]any {
	return object(map[string]any{
		"properties": map[string]any{
			"enabled":    boolSchema(),
			"audit-mode": boolSchema(),
		},
	})
}

func gatewayAPISchema() map[string]any {
	return object(map[string]any{
		"properties": map[string]any{
			"enabled":          boolSchema(),
			"host-network":     boolSchema(),
			"privileged-ports": boolSchema(),
		},
	})
}

func nativeRoutingSchema() map[string]any {
	return object(map[string]any{
		"required": []string{"ipv4-cidr"},
		"properties": map[string]any{
			"enabled":       boolSchema(),
			"ipv4-cidr":     map[string]any{"type": "string", "format": "cidr"},
			"direct-routes": boolSchema(),
		},
	})
}

func masqueradeSchema() map[string]any {
	return object(map[string]any{
		"properties": map[string]any{
			"enabled": boolSchema(),
			"bpf":     boolSchema(),
		},
	})
}

func sopsSchema() map[string]any {
	return object(map[string]any{
		"properties": map[string]any{
			"gpg": stringSchema(),
			"age": stringSchema(),
		},
	})
}

func fluxSchema() map[string]any {
	return object(map[string]any{
		"properties": map[string]any{
			"components":       stringSchema(),
			"components-extra": stringSchema(),
			"all-namespaces":   boolSchema(),
			"network-policy":   boolSchema(),
		},
	})
}

func controlPlaneSchema() map[string]any {
	return object(map[string]any{
		"required": []string{"nodes"},
		"properties": map[string]any{
			"record":             stringSchema(),
			"record-as-endpoint": boolSchema(),
			"patches":            stringList(true),
			"nodes":              nodesSchema(true),
		},
	})
}

func workerSchema() map[string]any {
	return object(map[string]any{
		"properties": map[string]any{
			"patches": stringList(true),
			"nodes":   nodesSchema(false),
		},
	})
}

func nodesSchema(required bool) map[string]any {
	s := object(map[string]any{
		"additionalProperties": stringList(true),
	})
	if required {
		s["minProperties"] = 1
	}
	return s
}

func enabledSchema() map[string]any {
	return object(map[string]any{
		"properties": map[string]any{
			"enabled": boolSchema(),
		},
	})
}

func object(fields map[string]any) map[string]any {
	fields["type"] = "object"
	if _, ok := fields["additionalProperties"]; !ok {
		fields["additionalProperties"] = false
	}
	return fields
}

func stringList(unique bool) map[string]any {
	return map[string]any{
		"type":        "array",
		"items":       stringSchema(),
		"uniqueItems": unique,
	}
}

func stringSchema() map[string]any {
	return map[string]any{"type": "string"}
}

func boolSchema() map[string]any {
	return map[string]any{"type": "boolean"}
}
