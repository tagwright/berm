// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Package label is the parsed model of berm's label grammar. It holds the
// types only. The parser that turns a container's raw labels into a
// ContainerSpec, and the validation that makes an unknown suffix or an
// ungranted reference a skip-and-alert error, is a later chunk. The grammar
// these types encode is frozen: see the wiki page "Berm Label Grammar
// (Draft)" for the authoritative definition of every label and sentinel.
//
// The grammar's berm.delivery enum is delivery.Mechanism, reused here rather
// than redefined, so there is one source of truth for client, hook, and
// volume across the label model and the delivery seam.
package label

import (
	"github.com/tagwright/berm/internal/delivery"
)

// Recognized label prefixes. The reader strips whichever matches, then parses
// one canonical suffix grammar. The same suffix under both prefixes with
// different values is a validation error (the ballast conflict rule, inherited
// verbatim).
const (
	// PrimaryPrefix is the short, tool-branded form, led with everywhere.
	PrimaryPrefix = "berm."

	// AliasPrefix is the org-namespaced alias. Its suffixes are identical to
	// the primary set.
	AliasPrefix = "tagwright.secret."
)

// RefKind is which of the three ref shapes a Ref is.
type RefKind int

const (
	// RefKey is a bare KEY: read that key from the container's default source.
	RefKey RefKind = iota

	// RefSourceKey is source/KEY: read a named key from a named dotenv source.
	RefSourceKey

	// RefSource is a bare source: take the whole payload of a source. Valid
	// only for a source whose format is binary.
	RefSource
)

// Ref is a parsed secret reference. The grammar is:
//
//	ref := KEY | source "/" KEY | source
//
// Source names are lowercase identifiers with digits and dashes. Keys are
// dotenv-env-var shaped (uppercase, digits, underscores, not leading with a
// digit). The two character classes never overlap, so the single "/"
// separator is unambiguous and no escaping is ever needed.
type Ref struct {
	// Kind is which shape this ref took.
	Kind RefKind

	// Source is the named source, empty for a bare-KEY ref (which resolves
	// against the container's default source).
	Source string

	// Key is the dotenv key, empty for a bare-source ref.
	Key string
}

// EnvDelivery is one resolved env-var delivery. Env is the exposed path and is
// legal only in client mode and only with berm.env.acknowledge on the
// container.
type EnvDelivery struct {
	// Var is the target environment variable name. For the berm.env list form
	// it equals the ref's Key; for the berm.env.<VAR> rename form it is <VAR>.
	Var string

	// Ref names what to deliver, unless All is set.
	Ref Ref

	// All is the berm.env "all" sentinel, legal only on the container's own
	// owned default source. When set, Ref is unused.
	All bool
}

// FileDelivery is one resolved file delivery, the secure default path.
type FileDelivery struct {
	// Name is the delivery name from berm.file.<name>.*.
	Name string

	// From names what to deliver. Defaults to the default source's whole
	// payload when that source is binary.
	From Ref

	// Path is the absolute, tmpfs-backed destination. Default /run/berm/<name>.
	Path string

	// Owner is uid[:gid], numeric only. Empty inherits the container default.
	Owner string

	// Mode is an octal string. Empty inherits the container default.
	Mode string
}

// ContainerSpec is the parsed berm intent for one container: its identity, its
// default source, its delivery mechanism, and every declared delivery. A later
// chunk produces it from a container's raw labels and validates it.
type ContainerSpec struct {
	// Enabled is berm.enable. A container is inert without it.
	Enabled bool

	// Name is the service identity (berm.name), keying the default source and
	// the scoping identity. Empty means the compose service name.
	Name string

	// Source is the default source (berm.source) for bare-KEY refs and
	// whole-source renders. Empty means the service name.
	Source string

	// Delivery is the resolved mechanism (berm.delivery). Empty means the
	// BERM_DEFAULT_DELIVERY / per-runtime default.
	Delivery delivery.Mechanism

	// Volume is the tmpfs mount name for volume-mode delivery (berm.volume).
	// Empty means berm-<service>.
	Volume string

	// EnvAck is berm.env.acknowledge, the required per-container affirmation of
	// env exposure. Any Env delivery without it is a hard validation error.
	EnvAck bool

	// Env are the env deliveries (berm.env and berm.env.<VAR>).
	Env []EnvDelivery

	// Files are the file deliveries (berm.file.<name>.*).
	Files []FileDelivery

	// Dotenv is the berm.dotenv path: render the whole default source as one
	// dotenv file. Empty when unset.
	Dotenv string

	// Envdir is the berm.envdir path: render the whole default source
	// key-per-file. Empty when unset.
	Envdir string

	// Owner is the container-level default owner (berm.owner) for every file
	// delivery.
	Owner string

	// Mode is the container-level default mode (berm.mode) for every file
	// delivery.
	Mode string
}
