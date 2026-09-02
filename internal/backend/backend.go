// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package backend is berm's crypto seam. It defines the one interface the core
// speaks to turn an encrypted source into transient plaintext, phrased in
// berm's own nouns so the core never reimplements crypto and never speaks a
// backend's private vocabulary.
//
// The SOPS/age driver in sopsage.go is the complete v1 implementation and is
// what the first release ships. Infisical is a legitimate future second
// implementation behind this same seam, added on real demand, the way kopia
// waits behind ballast's engine interface. Cutting the seam now is not a
// halfway job: the first release ships one complete backend, and the seam is
// what lets a second one slot in later without the core caring.
package backend

import (
	"context"
	"errors"
	"io"
)

// ErrNotImplemented is returned by a driver method that is not wired up yet.
var ErrNotImplemented = errors.New("backend: not implemented")

// ErrWrongFormat is returned when a caller uses a dotenv method on a binary
// source or a binary method on a dotenv source. Payload type is a property of
// the source in berm.yml and is enforced here, never guessed from a label.
var ErrWrongFormat = errors.New("backend: operation does not match the source format")

// ErrNoSuchKey is returned when a dotenv source has no entry for a requested
// key.
var ErrNoSuchKey = errors.New("backend: no such key in source")

// SourceFormat is how an encrypted source's plaintext is shaped. A dotenv
// source is a set of KEY to value pairs. A binary source is one opaque
// payload. The format is declared once, in berm.yml, and never restated in a
// label.
type SourceFormat string

const (
	// FormatDotenv is a set of KEY to value pairs, KEY being dotenv-env-var
	// shaped.
	FormatDotenv SourceFormat = "dotenv"

	// FormatBinary is one opaque payload delivered whole.
	FormatBinary SourceFormat = "binary"
)

// Valid reports whether f is a recognized format.
func (f SourceFormat) Valid() bool {
	return f == FormatDotenv || f == FormatBinary
}

// Sealed names one encrypted source for a backend to open. It carries no
// plaintext: only the ciphertext location, the source's declared format, and
// the name of the key that unseals it. Every field is resolved from berm.yml,
// which holds names and paths and never a secret value.
type Sealed struct {
	// Name is the source name from berm.yml, used only for diagnostics.
	Name string

	// Path is the resolved ciphertext path (a berm.yml file entry resolved
	// under BERM_SOURCES_ROOT).
	Path string

	// Format is the source's declared plaintext shape.
	Format SourceFormat

	// KeyRef is the age key name from berm.yml age_keys that unseals this
	// source. The backend maps it to a key path. The key itself never leaves
	// the daemon.
	KeyRef string
}

// Backend unseals an encrypted source and exposes its plaintext through a
// short-lived Opened handle. It is the only crypto seam in berm.
type Backend interface {
	// Open unseals src and returns a handle over its plaintext. The caller must
	// Close the returned handle, which zeroizes any retained plaintext
	// best-effort. Open does no plaintext work itself beyond what a handle
	// needs, so a driver is free to defer decryption to the first read.
	Open(ctx context.Context, src Sealed) (Opened, error)
}

// Opened is a transient handle over one unsealed source's plaintext. Its
// usable methods follow the source's Format: a dotenv source answers Keys,
// Value, and WriteValue; a binary source answers Payload and WritePayload.
// A method that does not match the source's format returns ErrWrongFormat.
//
// Plaintext handling contract (see the security contract in the architecture
// doc). Two access shapes exist deliberately:
//
//   - WriteValue and WritePayload stream plaintext straight to a destination
//     io.Writer (a tmpfs file descriptor in practice) so the value need never
//     become a Go string and, with a streaming driver, need never land on Go's
//     managed heap at all. This is the preferred path and the secure default's
//     path for file delivery.
//   - Value and Payload return the plaintext as []byte, never string, for the
//     env-delivery path where the value genuinely must enter the process
//     environment in memory. The caller holds the []byte, never a string, and
//     zeroizes it best-effort after use.
//
// A future memguard-backed or straight-to-fd driver satisfies this interface
// with no signature change, which is the reason it is shaped around []byte and
// io.Writer rather than string today.
type Opened interface {
	// Format reports the source's format so a caller can branch without
	// guessing.
	Format() SourceFormat

	// Keys lists the KEY names in a dotenv source, in file order. It exposes
	// names, never values. ErrWrongFormat on a binary source.
	Keys() ([]string, error)

	// Value returns one dotenv KEY's plaintext value as bytes. ErrNoSuchKey if
	// the key is absent, ErrWrongFormat on a binary source. Prefer WriteValue
	// for file delivery; Value exists for the env path that must hold the value
	// in process memory.
	Value(key string) ([]byte, error)

	// WriteValue streams one dotenv KEY's plaintext value to dst and returns
	// the byte count. ErrNoSuchKey if absent, ErrWrongFormat on a binary
	// source. This is the preferred value-delivery path.
	WriteValue(dst io.Writer, key string) (int64, error)

	// Payload returns a binary source's whole plaintext payload as bytes.
	// ErrWrongFormat on a dotenv source. Prefer WritePayload for file delivery.
	Payload() ([]byte, error)

	// WritePayload streams a binary source's whole payload to dst and returns
	// the byte count. ErrWrongFormat on a dotenv source. This is the preferred
	// binary-delivery path.
	WritePayload(dst io.Writer) (int64, error)

	// Close releases the handle and zeroizes retained plaintext best-effort.
	Close() error
}
