// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/config"
)

// Opener resolves a source name to a decrypt handle and to its ciphertext hash.
// It is the one seam the delivery core needs onto berm.yml plus the backend, so
// the writer, the render expansion, and the client-fetch handler never touch
// config or build a backend.Sealed themselves. The daemon provides a
// config-backed Opener; a test provides a fake one over fixture plaintext.
type Opener interface {
	// OpenSource unseals the named source and returns a handle over its
	// plaintext. The caller Closes the handle, which zeroizes retained
	// plaintext best-effort.
	OpenSource(ctx context.Context, source string) (backend.Opened, error)

	// SourceCipherHash returns a stable hex hash of the named source's
	// ciphertext at rest. The ciphertext is encrypted, so the hash leaks no
	// value. It is what the manifest records per injection and what the
	// staleness ledger (a later chunk) compares to detect a rotated source.
	SourceCipherHash(source string) (string, error)
}

// ConfigOpener is the daemon's Opener: it resolves a source name against a
// loaded berm.yml (path under BERM_SOURCES_ROOT, format, age key) into a
// backend.Sealed and drives the backend to open it. It holds no plaintext and
// no key material, only the config and the backend seam.
type ConfigOpener struct {
	cfg *config.Config
	be  backend.Backend
}

// NewConfigOpener builds an Opener from a loaded config and a backend.
func NewConfigOpener(cfg *config.Config, be backend.Backend) *ConfigOpener {
	return &ConfigOpener{cfg: cfg, be: be}
}

// sealed resolves a source name to a backend.Sealed, or an error naming the
// source (never a value). A relative file path resolves under
// BERM_SOURCES_ROOT, matching berm.yml's contract.
func (o *ConfigOpener) sealed(source string) (backend.Sealed, error) {
	src, ok := o.cfg.Sources[source]
	if !ok {
		return backend.Sealed{}, fmt.Errorf("delivery: source %q is not defined in berm.yml", source)
	}
	format := backend.FormatDotenv
	if src.Format != "" {
		format = backend.SourceFormat(src.Format)
	}
	return backend.Sealed{
		Name:   source,
		Path:   o.resolvePath(src.File),
		Format: format,
		KeyRef: src.AgeKey,
	}, nil
}

// resolvePath resolves a berm.yml file entry: absolute as-is, relative under
// BERM_SOURCES_ROOT.
func (o *ConfigOpener) resolvePath(file string) string {
	if filepath.IsAbs(file) || o.cfg.Globals.SourcesRoot == "" {
		return file
	}
	return filepath.Join(o.cfg.Globals.SourcesRoot, file)
}

// OpenSource satisfies Opener.
func (o *ConfigOpener) OpenSource(ctx context.Context, source string) (backend.Opened, error) {
	s, err := o.sealed(source)
	if err != nil {
		return nil, err
	}
	return o.be.Open(ctx, s)
}

// SourceCipherHash satisfies Opener by hashing the source's ciphertext file. It
// streams the file through sha256 so a large source is not pulled whole into
// memory, and the bytes are ciphertext regardless.
func (o *ConfigOpener) SourceCipherHash(source string) (string, error) {
	s, err := o.sealed(source)
	if err != nil {
		return "", err
	}
	f, err := os.Open(s.Path)
	if err != nil {
		return "", fmt.Errorf("delivery: open ciphertext for %q: %w", source, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("delivery: hash ciphertext for %q: %w", source, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

var _ Opener = (*ConfigOpener)(nil)
