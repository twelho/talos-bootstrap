// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads, parses, and validates a YAML config file. It does NOT change
// the process working directory: file/dir validation tags are evaluated
// against the config file's directory. Callers that later resolve relative
// paths from the config (e.g. talos.Generate's OutputDir, the patches and
// manifests directories) are expected to chdir to the returned dir first.
// The returned string is the directory containing the config file.
func Load(path string) (*Config, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("resolve config path: %w", err)
	}
	dir := filepath.Dir(abs)

	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, dir, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, dir, fmt.Errorf("parse config: %w", err)
	}

	if err := newValidator(dir).Struct(&cfg); err != nil {
		return nil, dir, formatErrors(err)
	}

	return &cfg, dir, nil
}

// FQDN joins the given host parts with the cluster's domain. Parts that are
// IP literals, equal to the domain, or already FQDNs under the domain bypass
// the join so we never double-append (e.g. "worker.example.com" + ".example.com").
// Empty parts are dropped so an unconditionally-included optional record
// (e.g. ControlPlane.Record) does not produce a leading dot.
func (c *Cluster) FQDN(parts ...string) string {
	nonEmpty := slices.DeleteFunc(slices.Clone(parts), func(s string) bool { return s == "" })
	if len(nonEmpty) == 1 && net.ParseIP(nonEmpty[0]) != nil {
		return nonEmpty[0]
	}
	joined := strings.Join(nonEmpty, ".")
	switch {
	case c.Domain == "":
		return joined
	case joined == "":
		return c.Domain
	case joined == c.Domain, strings.HasSuffix(joined, "."+c.Domain):
		return joined
	default:
		return joined + "." + c.Domain
	}
}
