// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

// Package sops creates the in-cluster secrets that Mozilla SOPS needs to
// decrypt encrypted resources reconciled by Flux. Two backends are supported:
// a GPG keyring entry (looked up via the local gpg agent) and an age key file.
//
// GPG export shells out to `gpg` because reimplementing the agent/keyring
// lookup in Go would mean either adopting a private-key store of our own or
// pulling in heavy crypto code that duplicates what gpg already does well.
// Age, by contrast, is a flat file we can simply read.
//
// The GPG path assumes the user's gpg-agent is unlocked and able to satisfy
// the export non-interactively. A passphrase-protected key with no preloaded
// agent will block the bootstrap on a pinentry that talos-bootstrap does not
// connect to a TTY.
package sops

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/twelho/talos-bootstrap/internal/kube"
)

const (
	Namespace     = "flux-system"
	GPGSecretName = "sops-gpg"
	AgeSecretName = "sops-age"
	gpgFileKey    = "sops.asc"
	ageFileKey    = "age.agekey"
)

// EnsureGPG exports the secret half of the GPG key with the given identifier
// (fingerprint, email, or name) and stores it as a Kubernetes secret. Skipped
// if the secret already exists; SOPS keys are write-once for this tool.
func EnsureGPG(ctx context.Context, c *kube.Client, keyID string) error {
	exists, err := c.ResourceExists(ctx, kube.GroupVersionResource{
		Version: "v1", Resource: "secrets",
	}, Namespace, GPGSecretName)
	if err != nil {
		return fmt.Errorf("check gpg secret: %w", err)
	}
	if exists {
		return nil
	}
	// Fail fast if the key isn't in the local keyring. Without this, the
	// export below would hang on a pinentry prompt for a missing key.
	if _, err := capture(ctx, "gpg", []string{"--batch", "--list-secret-keys", keyID}, nil); err != nil {
		return fmt.Errorf("gpg secret key %q not available locally: %w", keyID, err)
	}
	armored, err := exportGPGSecretKey(ctx, keyID)
	if err != nil {
		return fmt.Errorf("export gpg key %q: %w", keyID, err)
	}
	return c.EnsureSecret(ctx, Namespace, GPGSecretName, map[string][]byte{gpgFileKey: armored})
}

// EnsureAge reads the age key file and stores it as a Kubernetes secret.
// Skipped if the secret already exists.
func EnsureAge(ctx context.Context, c *kube.Client, keyPath string) error {
	exists, err := c.ResourceExists(ctx, kube.GroupVersionResource{
		Version: "v1", Resource: "secrets",
	}, Namespace, AgeSecretName)
	if err != nil {
		return fmt.Errorf("check age secret: %w", err)
	}
	if exists {
		return nil
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read age key %q: %w", keyPath, err)
	}
	return c.EnsureSecret(ctx, Namespace, AgeSecretName, map[string][]byte{ageFileKey: data})
}

func exportGPGSecretKey(ctx context.Context, keyID string) ([]byte, error) {
	return capture(ctx, "gpg", []string{
		"--batch", "--yes",
		"--armor", "--export-secret-keys",
		keyID,
	}, nil)
}

func capture(ctx context.Context, name string, args []string, stdin io.Reader) ([]byte, error) {
	bin, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s not found in $PATH", name)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %v: %w (%s)", name, args, err, stderr.String())
	}
	return stdout.Bytes(), nil
}
