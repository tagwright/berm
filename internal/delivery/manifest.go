// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package delivery

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/tagwright/berm/internal/wire"
)

// DefaultManifestPath is where the manifest lands, on tmpfs. Its atomic
// appearance (temp-then-rename within this same tmpfs directory) is the volume
// waiter's ready signal: the manifest exists only once every declared secret
// for the container is in place. It is defined once in the leaf wire package so
// the daemon and the client agree on it.
const DefaultManifestPath = wire.DefaultManifestPath

// manifestVersion is the manifest schema version, bumped when fields change so
// a reader can refuse a shape it does not understand.
const manifestVersion = 1

// Manifest records what berm delivered to one container: names, target paths,
// timestamps, and a ciphertext hash per injection. It NEVER records a secret
// value. The staleness ledger (a later chunk) consumes the ciphertext hashes to
// report which containers hold a source that changed since their last
// injection. It is serialized as JSON, whose field order is stable.
type Manifest struct {
	Version   int              `json:"version"`
	Container string           `json:"container"`
	Service   string           `json:"service"`
	Mechanism string           `json:"mechanism"`
	Generated string           `json:"generated"`
	Files     []ManifestFile   `json:"files,omitempty"`
	Renders   []ManifestRender `json:"renders,omitempty"`
	Env       []ManifestEnv    `json:"env,omitempty"`
}

// ManifestFile is one delivered file: its name, tmpfs path, ownership, source,
// the source's ciphertext hash, and the non-secret pointer var if one was set.
type ManifestFile struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Owner      string `json:"owner"`
	Mode       string `json:"mode"`
	Source     string `json:"source"`
	CipherHash string `json:"cipher_hash"`
	PointerVar string `json:"pointer_var,omitempty"`
}

// ManifestRender is one whole-source render: its kind, target path, source, and
// the source's ciphertext hash.
type ManifestRender struct {
	Kind       string `json:"kind"`
	Path       string `json:"path"`
	Source     string `json:"source"`
	CipherHash string `json:"cipher_hash"`
}

// ManifestEnv is one env delivery, recorded by NAME only: the var, its source
// and key (or the all sentinel), and the source's ciphertext hash. No value.
type ManifestEnv struct {
	Var        string `json:"var,omitempty"`
	Source     string `json:"source"`
	Key        string `json:"key,omitempty"`
	All        bool   `json:"all,omitempty"`
	CipherHash string `json:"cipher_hash"`
}

// BuildManifest produces the manifest for a plan. It records names, paths,
// timestamps, and one ciphertext hash per source, and never opens a secret: the
// hashes come from the source ciphertext at rest, which carries no plaintext.
// The clock is injectable so a test can pin the timestamp.
func BuildManifest(plan Plan, opener Opener, now time.Time) (*Manifest, error) {
	hashes := map[string]string{}
	hashOf := func(source string) (string, error) {
		if h, ok := hashes[source]; ok {
			return h, nil
		}
		h, err := opener.SourceCipherHash(source)
		if err != nil {
			return "", err
		}
		hashes[source] = h
		return h, nil
	}

	m := &Manifest{
		Version:   manifestVersion,
		Container: plan.Container,
		Service:   plan.Service,
		Mechanism: string(plan.Mechanism),
		Generated: now.UTC().Format(time.RFC3339),
	}

	for _, ft := range plan.Files {
		h, err := hashOf(ft.Source)
		if err != nil {
			return nil, err
		}
		m.Files = append(m.Files, ManifestFile{
			Name: ft.Name, Path: ft.Path, Owner: ft.Owner, Mode: ft.Mode,
			Source: ft.Source, CipherHash: h, PointerVar: ft.PointerVar,
		})
	}
	for _, rt := range plan.Renders {
		h, err := hashOf(rt.Source)
		if err != nil {
			return nil, err
		}
		m.Renders = append(m.Renders, ManifestRender{
			Kind: string(rt.Kind), Path: rt.Path, Source: rt.Source, CipherHash: h,
		})
	}
	for _, et := range plan.Env {
		h, err := hashOf(et.Source)
		if err != nil {
			return nil, err
		}
		m.Env = append(m.Env, ManifestEnv{
			Var: et.Var, Source: et.Source, Key: et.Key, All: et.All, CipherHash: h,
		})
	}
	return m, nil
}

// Marshal serializes the manifest to stable, indented JSON.
func (m *Manifest) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("delivery: marshal manifest: %w", err)
	}
	return b, nil
}

// WriteManifest lands the serialized manifest atomically at path (default
// DefaultManifestPath) on tmpfs. The manifest is non-secret, but it still lands
// on tmpfs and via temp-then-rename, because its atomic appearance is the ready
// signal a waiter blocks on. Mode 0444, owner 0:0, so any process in the
// container can read the signal.
func WriteManifest(path string, data []byte, requireTmpfs bool) error {
	if err := wire.WriteBytesFile(path, "0:0", "0444", requireTmpfs, data); err != nil {
		return fmt.Errorf("delivery: write manifest: %w", err)
	}
	return nil
}
