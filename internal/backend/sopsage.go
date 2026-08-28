// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package backend

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/awnumar/memguard"
)

// SOPSAge is the SOPS/age driver, berm's complete v1 backend. It drives the
// sops binary as a subprocess to decrypt a SOPS-encrypted dotenv or binary
// source with an age key held only by the daemon, and hands the plaintext to
// the resolver through an Opened handle. It never writes plaintext to
// persistent disk and never logs a value.
//
// Driving sops rather than reimplementing crypto keeps berm GPL-clean and, more
// importantly, lets plaintext stream from the sops pipe straight into a
// destination file descriptor without ever entering Go's managed heap on the
// preferred path. The paths that must parse a dotenv KEY or hand a value to the
// process environment pull plaintext into a memguard LockedBuffer instead, held
// in locked, non-swappable memory and destroyed as early as possible.
//
// The age key never enters this process. sops reads it itself from the
// SOPS_AGE_KEY_FILE path set in the minimal subprocess environment. berm holds
// only the path, never the key material, and never passes it on argv.
type SOPSAge struct {
	// keyPaths maps an age key name from berm.yml age_keys to its host path.
	// The key material itself is never held here, only the path to it.
	keyPaths map[string]string
}

// NewSOPSAge builds the SOPS/age backend from the age-key name-to-path map in
// berm.yml. The key files are read transiently by the sops subprocess at
// decrypt time, never cached as plaintext here.
func NewSOPSAge(keyPaths map[string]string) *SOPSAge {
	return &SOPSAge{keyPaths: keyPaths}
}

// defaultAgeKey is the age key name a source falls back to when it names none,
// matching berm.yml's "age_key defaults to default" rule.
const defaultAgeKey = "default"

// Open satisfies Backend. It validates the source's format, resolves its age
// key name to a host path, and confirms both the key file and the ciphertext
// file exist, then returns a handle. It does no plaintext work: decryption is
// deferred to the first read on the handle, so opening a source costs nothing
// until a secret is actually pulled from it. Every failure here is a typed
// error the resolver can classify, and none of them names a value.
func (s *SOPSAge) Open(ctx context.Context, src Sealed) (Opened, error) {
	if !src.Format.Valid() {
		return nil, wrapSource(fmt.Errorf("%w: %q", ErrWrongFormat, src.Format), src.Name)
	}

	keyName := src.KeyRef
	if keyName == "" {
		keyName = defaultAgeKey
	}
	keyPath, ok := s.keyPaths[keyName]
	if !ok {
		return nil, wrapSource(fmt.Errorf("%w: %q", ErrUnknownAgeKey, keyName), src.Name)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return nil, wrapSource(fmt.Errorf("%w: %q file %q", ErrUnknownAgeKey, keyName, keyPath), src.Name)
	}
	if _, err := os.Stat(src.Path); err != nil {
		return nil, wrapSource(fmt.Errorf("%w: %q", ErrSourceMissing, src.Path), src.Name)
	}

	return &sopsAgeOpened{
		ctx:        ctx,
		name:       src.Name,
		format:     src.Format,
		cipherPath: src.Path,
		ageKeyPath: keyPath,
	}, nil
}

// sopsAgeOpened is the SOPS/age Opened handle. It holds no plaintext at rest,
// only the coordinates of a decrypt: the ciphertext path, the resolved age key
// path, and the source format. Each read runs sops fresh. Any LockedBuffer a
// read retains to back a returned []byte is recorded in retained and destroyed
// on Close, so every byte of plaintext this handle ever surfaced is zeroized
// best-effort when the caller is done.
//
// A handle is used by one goroutine at a time, as the resolver drives one
// delivery at a time, so the retained slice needs no lock.
type sopsAgeOpened struct {
	ctx        context.Context
	name       string
	format     SourceFormat
	cipherPath string
	ageKeyPath string

	retained []*memguard.LockedBuffer
}

// Format reports the source's format so a caller can branch without guessing.
func (o *sopsAgeOpened) Format() SourceFormat { return o.format }

// requireDotenv guards the dotenv-only methods against a binary source.
func (o *sopsAgeOpened) requireDotenv() error {
	if o.format != FormatDotenv {
		return wrapSource(ErrWrongFormat, o.name)
	}
	return nil
}

// requireBinary guards the binary-only methods against a dotenv source.
func (o *sopsAgeOpened) requireBinary() error {
	if o.format != FormatBinary {
		return wrapSource(ErrWrongFormat, o.name)
	}
	return nil
}

// Keys lists the KEY names in a dotenv source, in file order. It decrypts,
// reads the names out of the transient locked buffer, and destroys that buffer
// immediately: names are all it needs, so no value outlives the call. Names are
// not secrets. ErrWrongFormat on a binary source.
func (o *sopsAgeOpened) Keys() ([]string, error) {
	if err := o.requireDotenv(); err != nil {
		return nil, err
	}
	buf, err := captureDecrypt(newSopsCmd(o.ctx, o.format, o.cipherPath, o.ageKeyPath))
	if err != nil {
		return nil, wrapSource(err, o.name)
	}
	if buf == nil {
		return nil, nil
	}
	defer buf.Destroy()
	keys, err := dotenvKeys(buf.Bytes())
	if err != nil {
		return nil, wrapSource(err, o.name)
	}
	return keys, nil
}

// Value returns one dotenv KEY's plaintext value as bytes, held in locked
// memory that Close zeroizes. It decrypts into a transient locked buffer, finds
// the one value, copies just that value into its own locked buffer, and
// destroys the whole-source buffer at once, so the rest of the source's
// plaintext lives for the shortest possible window. The returned bytes are
// never a string. ErrNoSuchKey if the key is absent (surfaced for
// skip-and-alert, never an empty value), ErrWrongFormat on a binary source. No
// value is ever logged: an error names the key and source only.
func (o *sopsAgeOpened) Value(key string) ([]byte, error) {
	if err := o.requireDotenv(); err != nil {
		return nil, err
	}
	buf, err := captureDecrypt(newSopsCmd(o.ctx, o.format, o.cipherPath, o.ageKeyPath))
	if err != nil {
		return nil, wrapSource(err, o.name)
	}
	if buf == nil {
		return nil, wrapSource(fmt.Errorf("%w: %q", ErrNoSuchKey, key), o.name)
	}
	// From here the whole-source plaintext is live; destroy it as soon as the
	// one value is copied out, whatever path we leave by.
	value, found, ferr := dotenvFind(buf.Bytes(), key)
	if ferr != nil {
		buf.Destroy()
		return nil, wrapSource(ferr, o.name)
	}
	if !found {
		buf.Destroy()
		return nil, wrapSource(fmt.Errorf("%w: %q", ErrNoSuchKey, key), o.name)
	}
	out := o.copyLocked(value)
	buf.Destroy()
	return out, nil
}

// WriteValue streams one dotenv KEY's plaintext value to dst and returns the
// byte count. Extracting one key from a dotenv payload requires parsing, so
// this path necessarily pulls the whole-source plaintext into a locked buffer
// first, unlike WritePayload which is fully off-heap. The transient buffer is
// destroyed the moment the value is written. ErrNoSuchKey if absent,
// ErrWrongFormat on a binary source.
func (o *sopsAgeOpened) WriteValue(dst io.Writer, key string) (int64, error) {
	if err := o.requireDotenv(); err != nil {
		return 0, err
	}
	buf, err := captureDecrypt(newSopsCmd(o.ctx, o.format, o.cipherPath, o.ageKeyPath))
	if err != nil {
		return 0, wrapSource(err, o.name)
	}
	if buf == nil {
		return 0, wrapSource(fmt.Errorf("%w: %q", ErrNoSuchKey, key), o.name)
	}
	value, found, ferr := dotenvFind(buf.Bytes(), key)
	if ferr != nil {
		buf.Destroy()
		return 0, wrapSource(ferr, o.name)
	}
	if !found {
		buf.Destroy()
		return 0, wrapSource(fmt.Errorf("%w: %q", ErrNoSuchKey, key), o.name)
	}
	n, werr := dst.Write(value)
	buf.Destroy()
	if werr != nil {
		return int64(n), fmt.Errorf("backend: write value for %q (source %q): %w", key, o.name, werr)
	}
	return int64(n), nil
}

// Payload returns a binary source's whole plaintext payload as bytes, held in
// locked memory that Close zeroizes. Prefer WritePayload, which never brings the
// payload onto Go's heap at all. ErrWrongFormat on a dotenv source.
func (o *sopsAgeOpened) Payload() ([]byte, error) {
	if err := o.requireBinary(); err != nil {
		return nil, err
	}
	buf, err := captureDecrypt(newSopsCmd(o.ctx, o.format, o.cipherPath, o.ageKeyPath))
	if err != nil {
		return nil, wrapSource(err, o.name)
	}
	if buf == nil {
		return []byte{}, nil
	}
	o.retained = append(o.retained, buf)
	return buf.Bytes(), nil
}

// WritePayload streams a binary source's whole payload to dst and returns the
// byte count. This is the fully off-heap path: sops's stdout is wired straight
// to dst, so the payload flows kernel-pipe to the destination file descriptor
// and never enters a Go buffer or the managed heap. ErrWrongFormat on a dotenv
// source.
func (o *sopsAgeOpened) WritePayload(dst io.Writer) (int64, error) {
	if err := o.requireBinary(); err != nil {
		return 0, err
	}
	n, err := streamDecrypt(newSopsCmd(o.ctx, o.format, o.cipherPath, o.ageKeyPath), dst)
	if err != nil {
		return n, wrapSource(err, o.name)
	}
	return n, nil
}

// copyLocked copies src into a fresh locked buffer, records it for Close to
// destroy, and returns its bytes. The copy goes locked memory to locked memory:
// src is a view into the whole-source locked buffer, dst is this value's own
// locked buffer, and nothing transits the Go heap. An empty value is legal
// (a present KEY with an empty value), returned as a non-nil empty slice with
// no buffer to retain.
func (o *sopsAgeOpened) copyLocked(src []byte) []byte {
	if len(src) == 0 {
		return []byte{}
	}
	lb := memguard.NewBuffer(len(src))
	copy(lb.Bytes(), src)
	o.retained = append(o.retained, lb)
	return lb.Bytes()
}

// Close destroys every locked buffer this handle retained to back a returned
// []byte, zeroizing that plaintext best-effort, then releases the handle. It is
// safe to call more than once. After Close, any []byte a caller still holds from
// Value or Payload is wiped and must not be read.
func (o *sopsAgeOpened) Close() error {
	for _, lb := range o.retained {
		if lb != nil {
			lb.Destroy()
		}
	}
	o.retained = nil
	return nil
}

// Compile-time checks that the driver satisfies the seam.
var (
	_ Backend = (*SOPSAge)(nil)
	_ Opened  = (*sopsAgeOpened)(nil)
)
