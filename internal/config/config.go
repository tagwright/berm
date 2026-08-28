// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Package config is the berm.yml schema and its loader. berm.yml holds
// structure, not secrets: names, paths, formats, owners, and grants. Nothing
// in it is ever a secret value, so it is safe to commit. Names live in labels,
// structure lives here.
//
// The small surviving set of BERM_* environment globals is loaded alongside
// the file into Globals. These are env on the daemon container, not fields of
// the committed berm.yml, so they are read from the environment and not from
// the yaml body.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultClientTimeout is the BERM_CLIENT_TIMEOUT fallback: a client-mode
// container whose fetch does not arrive within this window alerts.
const DefaultClientTimeout = 30 * time.Second

// DefaultDigestSchedule is the BERM_DIGEST_SCHEDULE fallback for the
// rotation-drift digest cadence.
const DefaultDigestSchedule = "daily"

// Source is one encrypted source entry in berm.yml. It names the ciphertext
// file, its plaintext format, which age key unseals it, the service that owns
// it, and any additional services granted read. It never holds a secret value.
type Source struct {
	// File is the ciphertext path. A relative path resolves under
	// BERM_SOURCES_ROOT.
	File string `yaml:"file"`

	// Format is "dotenv" (the default when empty) or "binary".
	Format string `yaml:"format"`

	// AgeKey is a name from AgeKeys. Empty means "default".
	AgeKey string `yaml:"age_key"`

	// Owner is the service that owns this source. Empty means the source's own
	// name. The owner references its source with no grant needed.
	Owner string `yaml:"owner"`

	// Access lists additional service names granted read. Cross-service sharing
	// is declared twice: by the consumer's label and by this grant. No wildcard
	// grants in v1.
	Access []string `yaml:"access"`
}

// Defaults are the fleet defaults a label or a source may override. There is
// deliberately no fleet-wide owner override here (see the grammar's Globals
// section on cut footguns).
type Defaults struct {
	// Delivery is the default berm.delivery when a container sets none and
	// BERM_DEFAULT_DELIVERY is unset.
	Delivery string `yaml:"delivery"`

	// Mode is the default file mode, an octal string, e.g. "0400".
	Mode string `yaml:"mode"`
}

// Globals is the small set of BERM_* environment globals on the daemon
// container. They are env, not committed berm.yml fields, so Load reads them
// from the environment.
type Globals struct {
	// SourcesRoot is BERM_SOURCES_ROOT: the root under which relative Source
	// File paths resolve.
	SourcesRoot string

	// DefaultDelivery is BERM_DEFAULT_DELIVERY: the fleet default for
	// berm.delivery. When empty the daemon defaults it per runtime (Docker
	// client, Podman hook), which a later chunk applies.
	DefaultDelivery string

	// ClientTimeout is BERM_CLIENT_TIMEOUT: the client-mode fetch deadline,
	// default DefaultClientTimeout.
	ClientTimeout time.Duration

	// StaleDigest is BERM_STALE_DIGEST: whether the rotation-drift digest is
	// enabled.
	StaleDigest bool

	// DigestSchedule is BERM_DIGEST_SCHEDULE: the digest cadence, default
	// DefaultDigestSchedule.
	DigestSchedule string

	// Runtime is BERM_RUNTIME: which container runtime to drive, "docker" or
	// "podman". Empty means docker. It also decides the per-runtime default
	// delivery mechanism when BERM_DEFAULT_DELIVERY is unset (docker client,
	// podman hook).
	Runtime string

	// Socket is BERM_SOCKET: the container runtime socket path. Empty lets the
	// daemon fall back to the runtime's conventional socket.
	Socket string
}

// Config is a parsed berm.yml plus the loaded BERM_* globals.
type Config struct {
	// AgeKeys maps an age key name to its host path. The key files are read
	// only by the daemon and never enter a container.
	AgeKeys map[string]string `yaml:"age_keys"`

	// Sources maps a source name to its entry.
	Sources map[string]Source `yaml:"sources"`

	// Defaults are the fleet defaults.
	Defaults Defaults `yaml:"defaults"`

	// Globals holds the BERM_* environment globals, loaded from the
	// environment, not the yaml body.
	Globals Globals `yaml:"-"`
}

// Load reads and parses berm.yml at path, then overlays the BERM_*
// environment globals. A parse error is returned. Semantic validation (a
// source naming a nonexistent age key, a bad format, and so on) is a later
// chunk's job.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	cfg.Globals = loadGlobals()
	return &cfg, nil
}

// loadGlobals reads the BERM_* environment globals, applying defaults for the
// two that have them.
func loadGlobals() Globals {
	g := Globals{
		SourcesRoot:     os.Getenv("BERM_SOURCES_ROOT"),
		DefaultDelivery: os.Getenv("BERM_DEFAULT_DELIVERY"),
		ClientTimeout:   DefaultClientTimeout,
		StaleDigest:     boolEnv("BERM_STALE_DIGEST"),
		DigestSchedule:  DefaultDigestSchedule,
		Runtime:         os.Getenv("BERM_RUNTIME"),
		Socket:          os.Getenv("BERM_SOCKET"),
	}

	if v := os.Getenv("BERM_CLIENT_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			g.ClientTimeout = d
		}
	}
	if v := os.Getenv("BERM_DIGEST_SCHEDULE"); v != "" {
		g.DigestSchedule = v
	}
	return g
}

// boolEnv parses a BERM_* boolean, treating an unparseable or empty value as
// false.
func boolEnv(name string) bool {
	v := os.Getenv(name)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}
