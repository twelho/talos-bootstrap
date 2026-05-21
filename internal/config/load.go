// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads a YAML config file, validates it, and chdir's to the config's
// directory so that subsequent relative paths in the config resolve correctly.
// It returns the parsed Config and the absolute path of the config file.
func Load(path string) (*Config, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("resolve config path: %w", err)
	}

	if err := os.Chdir(filepath.Dir(abs)); err != nil {
		return nil, abs, fmt.Errorf("chdir to config dir: %w", err)
	}

	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, abs, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, abs, fmt.Errorf("parse config: %w", err)
	}

	if err := newValidator().Struct(&cfg); err != nil {
		return nil, abs, formatErrors(err)
	}

	return &cfg, abs, nil
}

// FQDN joins the given host parts with the cluster's domain (if any),
// dropping empty segments so callers can pass an unconditionally-included
// optional record without an extra branch.
func (c *Cluster) FQDN(parts ...string) string {
	all := slices.DeleteFunc(append(slices.Clone(parts), c.Domain), func(s string) bool {
		return s == ""
	})
	return strings.Join(all, ".")
}
