// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package config

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
)

// SchemaJSON returns a JSON Schema document for talos-bootstrap YAML
// configuration files. The schema is derived from the Config struct by
// reflection so that yaml tags drive property names and the subset of
// validator tags with JSON Schema equivalents (required, cidr, unique, min)
// drive the corresponding constraints. types.go is the single source of
// truth; this file only translates.
func SchemaJSON() ([]byte, error) {
	s := schemaFor(reflect.TypeOf(Config{}))
	s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	s["$id"] = "https://github.com/twelho/talos-bootstrap/schema/config.schema.json"
	s["title"] = "talos-bootstrap configuration"
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// schemaFor renders the JSON Schema fragment that describes t. Pointer types
// are transparently dereferenced; presence/absence is governed by the
// validator tag on the containing struct field, not by pointer-ness.
func schemaFor(t reflect.Type) map[string]any {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		return structSchema(t)
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": schemaFor(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaFor(t.Elem())}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	}
	return map[string]any{}
}

func structSchema(t reflect.Type) map[string]any {
	props := map[string]any{}
	var required []string
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := yamlName(f)
		if name == "-" {
			continue
		}
		sub := schemaFor(f.Type)
		applyValidate(f.Tag.Get("validate"), sub, &required, name)
		props[name] = sub
	}
	s := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func yamlName(f reflect.StructField) string {
	tag := f.Tag.Get("yaml")
	if tag == "" {
		return f.Name
	}
	return strings.SplitN(tag, ",", 2)[0]
}

// applyValidate interprets the subset of go-playground/validator tags that
// has a JSON Schema equivalent. Validators before `dive` apply to the field
// itself; validators after `dive` apply to the item / value schema (slice
// elements, or map values).
func applyValidate(tag string, schema map[string]any, required *[]string, name string) {
	if tag == "" {
		return
	}
	before, after, _ := strings.Cut(tag, "dive")
	applyValidateParts(strings.Trim(before, ","), schema, required, name)
	if after = strings.Trim(after, ","); after != "" {
		if items := itemsSchemaOf(schema); items != nil {
			applyValidateParts(after, items, nil, "")
		}
	}
}

func applyValidateParts(tag string, schema map[string]any, required *[]string, name string) {
	if tag == "" {
		return
	}
	omit := false
	for _, p := range strings.Split(tag, ",") {
		switch {
		case p == "":
		case p == "omitempty":
			omit = true
		case p == "required":
			if !omit && required != nil {
				*required = append(*required, name)
			}
		case strings.HasPrefix(p, "required_without="), strings.HasPrefix(p, "required_if="):
			// Cross-field rule with no clean JSON Schema mapping; enforced at
			// runtime by go-playground/validator.
		case p == "cidr":
			schema["format"] = "cidr"
		case p == "unique":
			if schema["type"] == "array" {
				schema["uniqueItems"] = true
			}
		case strings.HasPrefix(p, "min="):
			n, err := strconv.Atoi(strings.TrimPrefix(p, "min="))
			if err != nil {
				continue
			}
			switch schema["type"] {
			case "object":
				schema["minProperties"] = n
			case "array":
				schema["minItems"] = n
			}
		}
	}
}

// itemsSchemaOf returns the schema for the items of an array or for the
// values of an additionalProperties-typed object, whichever applies. Returns
// nil for scalar schemas.
func itemsSchemaOf(schema map[string]any) map[string]any {
	if items, ok := schema["items"].(map[string]any); ok {
		return items
	}
	if ap, ok := schema["additionalProperties"].(map[string]any); ok {
		return ap
	}
	return nil
}
