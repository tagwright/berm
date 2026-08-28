// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/awnumar/memguard"
)

// sopsBinary is the name of the sops executable the driver drives. It is
// resolved on PATH inside the minimal subprocess environment. It is a package
// variable so a test can point at a specific build, but it is never a path a
// caller controls at runtime.
var sopsBinary = "sops"

// Typed errors the resolver can classify. None of them ever carries a secret
// value: they name the source and the key, never the plaintext. ErrWrongFormat
// and ErrNoSuchKey live in backend.go alongside the seam.
var (
	// ErrSourceMissing is the ciphertext file named by the source is absent or
	// unreadable. Encrypted at rest, so naming its path leaks nothing.
	ErrSourceMissing = errors.New("backend: source ciphertext file is missing")

	// ErrUnknownAgeKey is the source names an age key that is not in berm.yml
	// age_keys, or that key's file is absent. Names a path, never key material.
	ErrUnknownAgeKey = errors.New("backend: age key is not known")

	// ErrDecrypt is sops exited nonzero: a wrong recipient or age key, a
	// corrupt or non-sops file. It carries the exit code and a short scrubbed
	// stderr head, never a secret. sops does not print secret values on a
	// decrypt error.
	ErrDecrypt = errors.New("backend: sops failed to decrypt the source")

	// ErrMalformed is the decrypted dotenv plaintext did not parse. It names the
	// source, never the offending value.
	ErrMalformed = errors.New("backend: source plaintext is malformed")
)

// stderrHead bounds how much of sops's stderr is retained for an error message.
// sops does not print secret values on a decrypt failure, but a short head is
// kept regardless so a future sops change cannot turn an error string into a
// leak channel.
const stderrHead = 512

// minimalEnv is the subprocess environment for sops: PATH so the binary and its
// helpers resolve, and SOPS_AGE_KEY_FILE pointing at the named key's host path.
// The daemon's full environment is deliberately NOT inherited, and the key is
// never passed on argv or copied into Go, only referenced by path in an env
// var sops reads itself.
func minimalEnv(ageKeyPath string) []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	return []string{
		"PATH=" + path,
		"SOPS_AGE_KEY_FILE=" + ageKeyPath,
	}
}

// decryptArgs is the sops argv for decrypting a source of the given format. The
// input and output type both match the source format: dotenv yields KEY=VALUE
// lines, binary yields one raw payload. The only path on the argv is the
// CIPHERTEXT file, which is encrypted at rest.
func decryptArgs(format SourceFormat, cipherPath string) []string {
	t := string(format)
	return []string{"-d", "--input-type", t, "--output-type", t, cipherPath}
}

// newSopsCmd builds the sops decrypt command with the minimal environment set.
// Stdout is left for the caller to wire, either straight to a destination
// (streaming, off-heap) or captured into locked memory (the parse and env
// paths).
func newSopsCmd(ctx context.Context, format SourceFormat, cipherPath, ageKeyPath string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, sopsBinary, decryptArgs(format, cipherPath)...)
	cmd.Env = minimalEnv(ageKeyPath)
	return cmd
}

// countWriter counts bytes forwarded to an inner writer without ever copying or
// inspecting them. It is how the streaming path reports a byte count while the
// plaintext flows kernel-pipe to destination and never through a Go buffer.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// streamDecrypt runs sops with Stdout wired DIRECTLY to dst, so plaintext flows
// from the sops pipe into the destination file descriptor and never lands on
// Go's managed heap. This is the off-heap path used for a binary source's whole
// payload. It returns the number of plaintext bytes written.
//
// On a sops failure the returned error is scrubbed to the exit code plus a
// short stderr head. Because bytes are streamed as they arrive, a failure that
// occurs partway may have already written a prefix to dst. The delivery layer
// treats a returned error as a failed delivery and discards its destination
// (an atomic tmpfs temp-then-rename), so a partial prefix is never published.
func streamDecrypt(cmd *exec.Cmd, dst io.Writer) (int64, error) {
	cw := &countWriter{w: dst}
	cmd.Stdout = cw
	var stderr bytes.Buffer
	cmd.Stderr = &boundedWriter{max: stderrHead, buf: &stderr}
	if err := cmd.Run(); err != nil {
		return cw.n, classifyExec(err, stderr.Bytes())
	}
	return cw.n, nil
}

// captureDecrypt runs sops and moves its whole stdout into a memguard
// LockedBuffer, returning that buffer for the caller to parse and then Destroy.
// This is the path that must hold plaintext to parse a dotenv KEY or to hand a
// value to the process environment. sops stdout is read into a transient Go
// slice (unavoidable, the size is not known ahead of time), then that slice is
// moved into locked, non-swappable memory and the transient wiped. A nil buffer
// with a nil error means the source decrypted to empty.
func captureDecrypt(cmd *exec.Cmd) (*memguard.LockedBuffer, error) {
	var stderr bytes.Buffer
	cmd.Stderr = &boundedWriter{max: stderrHead, buf: &stderr}
	out, err := cmd.Output()
	if err != nil {
		memguard.WipeBytes(out)
		return nil, classifyExec(err, stderr.Bytes())
	}
	if len(out) == 0 {
		return nil, nil
	}
	// NewBufferFromBytes copies out into locked memory and wipes out.
	return memguard.NewBufferFromBytes(out), nil
}

// classifyExec turns a sops exec error into a typed, scrubbed backend error. A
// missing binary is a decrypt-path failure. A nonzero exit is ErrDecrypt with
// the exit code and the bounded stderr head appended, which sops guarantees not
// to fill with a secret value on a decrypt error and which is bounded here
// regardless.
func classifyExec(err error, stderr []byte) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		head := bytes.TrimSpace(stderr)
		if len(head) > stderrHead {
			head = head[:stderrHead]
		}
		if len(head) == 0 {
			return fmt.Errorf("%w: exit %d", ErrDecrypt, exitErr.ExitCode())
		}
		return fmt.Errorf("%w: exit %d: %s", ErrDecrypt, exitErr.ExitCode(), head)
	}
	return fmt.Errorf("%w: %v", ErrDecrypt, err)
}

// boundedWriter keeps at most max bytes of what is written to it, discarding
// the rest. It caps sops stderr so a wrapped error can never grow without
// bound and can never carry more than a short head.
type boundedWriter struct {
	max int
	buf *bytes.Buffer
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) <= room {
			b.buf.Write(p)
		} else {
			b.buf.Write(p[:room])
		}
	}
	// Report the full length so the child process never blocks on a full pipe.
	return len(p), nil
}
