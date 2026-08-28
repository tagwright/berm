// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package backend

import (
	"context"
	"io"

	"github.com/awnumar/memguard"
)

// SOPSAge is the SOPS/age driver, berm's complete v1 backend. It decrypts a
// SOPS-encrypted dotenv or age-encrypted binary source with an age key held
// only by the daemon, and hands the plaintext to the resolver through an
// Opened handle. It never writes plaintext to persistent disk and never logs a
// value.
//
// The methods are stubbed until a later chunk fills them. The real driver will
// stream sops and age stdout into the destination file descriptor where
// possible, guard the transient plaintext window with memguard, and zeroize
// best-effort on Close.
type SOPSAge struct {
	// keyPaths maps an age key name from berm.yml age_keys to its host path.
	// A later chunk populates and reads it. The key material itself is never
	// held here, only the path to it.
	keyPaths map[string]string
}

// NewSOPSAge builds the SOPS/age backend from the age-key name-to-path map in
// berm.yml. The key files are read transiently at decrypt time, never cached
// as plaintext here.
func NewSOPSAge(keyPaths map[string]string) *SOPSAge {
	return &SOPSAge{keyPaths: keyPaths}
}

// Open satisfies Backend. Stubbed until the driver chunk.
func (s *SOPSAge) Open(_ context.Context, _ Sealed) (Opened, error) {
	return nil, ErrNotImplemented
}

// sopsAgeOpened is the SOPS/age Opened handle. Stubbed until the driver chunk.
// The plaintext field is the transient decrypted window the real driver will
// hold as []byte (never a string) and wipe on Close.
type sopsAgeOpened struct {
	format    SourceFormat
	plaintext []byte
}

func (o *sopsAgeOpened) Format() SourceFormat                            { return o.format }
func (o *sopsAgeOpened) Keys() ([]string, error)                         { return nil, ErrNotImplemented }
func (o *sopsAgeOpened) Value(_ string) ([]byte, error)                  { return nil, ErrNotImplemented }
func (o *sopsAgeOpened) WriteValue(_ io.Writer, _ string) (int64, error) { return 0, ErrNotImplemented }
func (o *sopsAgeOpened) Payload() ([]byte, error)                        { return nil, ErrNotImplemented }
func (o *sopsAgeOpened) WritePayload(_ io.Writer) (int64, error)         { return 0, ErrNotImplemented }

// Close zeroizes the transient plaintext window best-effort, per the security
// contract, then releases the handle. memguard.WipeBytes is the best-effort
// wipe the real driver will pair with a memguard-guarded plaintext buffer.
func (o *sopsAgeOpened) Close() error {
	if o.plaintext != nil {
		memguard.WipeBytes(o.plaintext)
		o.plaintext = nil
	}
	return nil
}

// Compile-time checks that the stubs satisfy the seam.
var (
	_ Backend = (*SOPSAge)(nil)
	_ Opened  = (*sopsAgeOpened)(nil)
)
