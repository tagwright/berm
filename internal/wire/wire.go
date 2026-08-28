// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Package wire is berm's leaf shared-delivery core: the on-socket protocol
// between the daemon and the one-shot client, the secret Bundle those two
// exchange, and the tmpfs file primitive both the daemon-side writer and the
// client-side apply step use to land a secret on a container's tmpfs.
//
// It is deliberately a leaf. It imports only the standard library and memguard,
// never backend, resolve, config, or delivery, so the tiny berm-client binary
// links it without dragging in the daemon's runtime and crypto stack, and so
// there is no import cycle with the higher layers that consume it.
//
// Security contract (the spine, see the architecture doc). No plaintext ever
// reaches persistent disk. WriteTmpfsFile refuses a destination that is not a
// tmpfs or ramfs mount when RequireTmpfs is set, and writes temp-then-rename
// within that one tmpfs directory so a partial file is never published. The
// secret bytes a Bundle carries live in memguard LockedBuffers, off Go's
// managed heap where the platform allows locked memory, and Destroy zeroizes
// every one of them. The manifest a Bundle carries records names, paths,
// timestamps, and ciphertext hashes, never a secret value.
package wire

import "github.com/awnumar/memguard"

// DefaultManifestPath is where the manifest lands on the container tmpfs. Its
// atomic appearance is the volume waiter's ready signal. It lives here in the
// leaf so both the daemon-side generator and the client-side apply name one
// path without the client reaching into the delivery package.
const DefaultManifestPath = "/run/berm/manifest"

// ProtocolVersion is the leading version byte on every frame in both
// directions. It is bumped when the frame layout changes so an old client and
// a new daemon (or the reverse) fail loudly on a version mismatch instead of
// misparsing a secret payload. See docs/PROTOCOL.md for the full frame layout.
//
// Version 2 added the hook-request message type (msgHookRequest), which carries
// a container id, alongside the original fetch request (which carries no body).
const ProtocolVersion byte = 2

// Message type bytes, the second byte of every frame.
//
// There are deliberately two request types with two different trust models. The
// fetch request carries no body: the daemon derives the caller's identity from
// the kernel-attested peer credentials of the socket (SO_PEERCRED), so a client
// cannot ask for another container's secrets. The hook request carries a
// container id, because it comes from the OCI pre-start hook, a trusted
// privileged host-side injector the operator installs; it has no peer container
// identity of its own, so it presents the id of the container it is populating
// and the daemon validates that id has berm labels before it resolves anything.
// See docs/PROTOCOL.md for the full contrast.
const (
	// msgFetchRequest is the client's request for its bundle. The request
	// carries no body: the daemon derives the caller's identity from the peer
	// credentials of the socket itself, never from anything the client sends.
	msgFetchRequest byte = 1

	// msgBundleResponse is the daemon's successful reply, carrying the bundle.
	msgBundleResponse byte = 2

	// msgErrorResponse is the daemon's failure reply, carrying a short scrubbed
	// reason and never a secret value.
	msgErrorResponse byte = 3

	// msgHookRequest is the OCI pre-start hook's request for a container's file
	// bundle. It carries the OCI container id the hook read from the runtime
	// state on stdin. The daemon inspects that id, confirms it is berm-enabled,
	// resolves its plan, and returns its files only (env is refused in hook
	// mode). The id is presented by a trusted injector, not proven by peer
	// credentials, so the daemon validates it rather than trusting it blindly.
	msgHookRequest byte = 4
)

// File is one secret file in a bundle: where it lands on the container tmpfs,
// with what numeric owner and octal mode, and its plaintext bytes. The bytes
// live in a memguard LockedBuffer tracked by the owning Bundle, so Bundle.Destroy
// zeroizes them. A whole-source render is expanded into ordinary File entries by
// the daemon before it ever reaches the wire, so the client applies files and
// sets env and needs no knowledge of render semantics.
type File struct {
	// Path is the absolute, tmpfs-backed destination inside the container.
	Path string

	// Owner is the numeric uid or uid:gid to chown the file to.
	Owner string

	// Mode is the octal file mode, e.g. "0400".
	Mode string

	// Data is the plaintext, a view into a LockedBuffer the Bundle owns. It is
	// never a Go string.
	Data []byte
}

// EnvVar is one secret environment variable in a bundle: the variable name and
// its plaintext value bytes. Env crosses the wire only in client mode, the one
// mechanism that sets the process environment at exec. The value lives in a
// LockedBuffer the Bundle owns.
type EnvVar struct {
	// Name is the environment variable name to set at exec.
	Name string

	// Value is the plaintext value, a view into a LockedBuffer the Bundle owns.
	// It is never a Go string.
	Value []byte
}

// Pointer is one non-secret _FILE pointer: the environment variable name and
// the tmpfs path it points at. Its value is a path, not a secret, so it is a
// plain string and does not count against the env-exposure gate.
type Pointer struct {
	// Name is the pointer environment variable, e.g. "POSTGRES_PASSWORD_FILE".
	Name string

	// Path is the tmpfs path the pointer names. Not a secret.
	Path string
}

// Bundle is the complete set of secrets that belong to one caller and no other:
// the files to write, the env vars to set at exec, the non-secret _FILE pointers
// to set, and the serialized manifest to drop as the ready signal. It is what
// the client-fetch handler produces and the client applies.
//
// The secret bytes (every File.Data and EnvVar.Value) are backed by the locked
// buffers in locked. Destroy zeroizes and frees them. A caller MUST Destroy a
// Bundle once it is done with it: the daemon after it has serialized the bundle
// onto the connection, the client after it has applied every file and set every
// env var (immediately before exec).
type Bundle struct {
	// Files are the secret files to write to tmpfs, render expansions included.
	Files []File

	// Env are the secret env vars to set at exec. Client mode only.
	Env []EnvVar

	// Pointers are the non-secret _FILE pointer env vars to set. Client mode
	// only; in file-only modes the pointer is recorded in the manifest instead.
	Pointers []Pointer

	// Manifest is the serialized, non-secret manifest to write to the ready-
	// signal path. It records names, paths, timestamps, and ciphertext hashes,
	// never a value.
	Manifest []byte

	// locked owns every LockedBuffer backing a File.Data or EnvVar.Value, so
	// Destroy can zeroize them all. It is unexported: callers touch bytes only
	// through Files and Env.
	locked []*memguard.LockedBuffer
}

// track records a LockedBuffer for Destroy to zeroize and returns its bytes,
// so a builder can append a secret and hand its view to a File or EnvVar in one
// step. A nil buffer is ignored and yields a non-nil empty slice, which models
// a present-but-empty secret without allocating locked memory for zero bytes.
func (b *Bundle) track(lb *memguard.LockedBuffer) []byte {
	if lb == nil {
		return []byte{}
	}
	b.locked = append(b.locked, lb)
	return lb.Bytes()
}

// AddSecret copies src into a fresh locked buffer the bundle owns, tracks it for
// Destroy, and returns a view over the copy. The handler uses it to move a
// decrypted value out of a backend handle (whose own buffers are wiped when it
// Closes) into the bundle's independent locked memory. An empty src yields a
// non-nil empty slice and allocates no locked memory.
func (b *Bundle) AddSecret(src []byte) []byte {
	if len(src) == 0 {
		return []byte{}
	}
	lb := memguard.NewBuffer(len(src))
	copy(lb.Bytes(), src)
	return b.track(lb)
}

// Destroy zeroizes and frees every locked buffer backing a secret in the
// bundle, best-effort, and clears the slices so a stale view cannot be read
// after. It is safe to call more than once and safe to call on a zero Bundle.
// After Destroy, any File.Data or EnvVar.Value a caller still holds is wiped and
// must not be read.
func (b *Bundle) Destroy() {
	for _, lb := range b.locked {
		if lb != nil {
			lb.Destroy()
		}
	}
	b.locked = nil
	for i := range b.Files {
		b.Files[i].Data = nil
	}
	for i := range b.Env {
		b.Env[i].Value = nil
	}
}
