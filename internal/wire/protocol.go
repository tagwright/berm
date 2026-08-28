// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package wire

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/awnumar/memguard"
)

// The frame layout is documented in full in docs/PROTOCOL.md. In brief, every
// frame leads with ProtocolVersion and a message-type byte. The fetch request
// is those two bytes and nothing else: the daemon authenticates the caller from
// the socket's peer credentials, never from the request body. The response is
// either a bundle frame or an error frame. All multi-byte integers are
// big-endian. Byte strings are length-prefixed: u16 for names, paths, owners,
// modes, and error text, u32 for secret payloads and the manifest.

// maxField bounds any single length-prefixed field the decoder will accept, so
// a corrupt or hostile length cannot drive an unbounded allocation. It is far
// larger than any real secret file yet small enough to be a safe ceiling.
const maxField = 64 << 20 // 64 MiB

// RequestType classifies a request frame the daemon read the header of. The
// daemon dispatches on it: a fetch request runs the peer-authenticated client
// path, a hook request runs the trusted-injector hook path.
type RequestType int

const (
	// RequestFetch is a client fetch request. It carries no body.
	RequestFetch RequestType = iota

	// RequestHook is an OCI pre-start hook request. Its body is a container id,
	// read next with ReadHookBody.
	RequestHook
)

// WriteRequest writes a fetch request onto w. The client calls it after
// connecting. It carries no body.
func WriteRequest(w io.Writer) error {
	if _, err := w.Write([]byte{ProtocolVersion, msgFetchRequest}); err != nil {
		return fmt.Errorf("wire: write request: %w", err)
	}
	return nil
}

// WriteHookRequest writes a hook request onto w carrying the OCI container id
// and the container's OCI annotations. The hook binary calls it after
// connecting: unlike the client, the hook has no peer container identity of its
// own, so it presents the id AND the container's own config annotations (the
// berm.* keys the operator set, which the runtime handed the hook in the OCI
// state). The daemon resolves from these presented annotations rather than
// inspecting the container over the runtime API: the pre-start hook fires while
// the runtime holds the container-creation lock, so a daemon Inspect of that
// same container would deadlock against the create the hook is blocking. The
// hook is a trusted, privileged host-side component, so presenting the
// container's own annotations is consistent with that trust boundary. The
// annotations are not secret.
func WriteHookRequest(w io.Writer, containerID string, annotations map[string]string) error {
	if containerID == "" {
		return fmt.Errorf("wire: hook request needs a container id")
	}
	if _, err := w.Write([]byte{ProtocolVersion, msgHookRequest}); err != nil {
		return fmt.Errorf("wire: write hook request header: %w", err)
	}
	if err := writeU16Bytes(w, []byte(containerID)); err != nil {
		return err
	}
	return writeStringMap(w, annotations)
}

// ReadRequestHeader reads and validates the two-byte frame header from r and
// returns which request type it is. The daemon calls it first on an accepted
// connection, then dispatches: RequestFetch runs the peer-auth path (no more
// bytes to read), RequestHook is followed by ReadHookBody for the container id.
// A version mismatch or an unrecognized type is a hard, loud error.
func ReadRequestHeader(r io.Reader) (RequestType, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, fmt.Errorf("wire: read request header: %w", err)
	}
	if hdr[0] != ProtocolVersion {
		return 0, fmt.Errorf("wire: request protocol version %d, want %d", hdr[0], ProtocolVersion)
	}
	switch hdr[1] {
	case msgFetchRequest:
		return RequestFetch, nil
	case msgHookRequest:
		return RequestHook, nil
	default:
		return 0, fmt.Errorf("wire: request message type %d is not recognized", hdr[1])
	}
}

// ReadHookBody reads the container id and the container's OCI annotations that
// follow a hook request header. The daemon calls it after ReadRequestHeader
// returns RequestHook. The id is a length-prefixed byte string; the annotations
// are a length-prefixed key/value map. Both are bounded by the field caps, so a
// hostile length cannot drive an unbounded allocation.
func ReadHookBody(r io.Reader) (string, map[string]string, error) {
	id, err := readU16String(r)
	if err != nil {
		return "", nil, fmt.Errorf("wire: read hook container id: %w", err)
	}
	if id == "" {
		return "", nil, fmt.Errorf("wire: hook request carried an empty container id")
	}
	ann, err := readStringMap(r)
	if err != nil {
		return "", nil, fmt.Errorf("wire: read hook annotations: %w", err)
	}
	return id, ann, nil
}

// ReadRequest reads and validates a fetch request from r. It is the fetch-only
// convenience retained for the client path and its tests: it fails on any
// non-fetch request. The daemon's dispatch loop uses ReadRequestHeader instead,
// so it can accept both request types.
func ReadRequest(r io.Reader) error {
	rt, err := ReadRequestHeader(r)
	if err != nil {
		return err
	}
	if rt != RequestFetch {
		return fmt.Errorf("wire: request is not a fetch request")
	}
	return nil
}

// ReadHookRequest reads and validates a whole hook request from r (header and
// body) and returns the container id and its annotations. It is the symmetric
// counterpart to WriteHookRequest for direct use and tests; the daemon loop uses
// ReadRequestHeader plus ReadHookBody so it can dispatch on the type first.
func ReadHookRequest(r io.Reader) (string, map[string]string, error) {
	rt, err := ReadRequestHeader(r)
	if err != nil {
		return "", nil, err
	}
	if rt != RequestHook {
		return "", nil, fmt.Errorf("wire: request is not a hook request")
	}
	return ReadHookBody(r)
}

// WriteError writes an error response frame onto w carrying a short reason. The
// daemon calls it when it cannot produce a bundle. The reason must never carry
// a secret value; callers pass a scrubbed string.
func WriteError(w io.Writer, reason string) error {
	if _, err := w.Write([]byte{ProtocolVersion, msgErrorResponse}); err != nil {
		return fmt.Errorf("wire: write error header: %w", err)
	}
	return writeU16Bytes(w, []byte(reason))
}

// EncodeBundle writes b as a bundle response frame onto w. The daemon calls it
// once the handler has produced the caller's bundle. It streams the secret
// bytes straight from their locked buffers onto the connection and never copies
// them onto Go's heap. The caller Destroys b after EncodeBundle returns.
func EncodeBundle(w io.Writer, b *Bundle) error {
	if _, err := w.Write([]byte{ProtocolVersion, msgBundleResponse}); err != nil {
		return fmt.Errorf("wire: write bundle header: %w", err)
	}

	if err := writeU32(w, uint32(len(b.Files))); err != nil {
		return err
	}
	for _, f := range b.Files {
		if err := writeU16Bytes(w, []byte(f.Path)); err != nil {
			return err
		}
		if err := writeU16Bytes(w, []byte(f.Owner)); err != nil {
			return err
		}
		if err := writeU16Bytes(w, []byte(f.Mode)); err != nil {
			return err
		}
		if err := writeU32Bytes(w, f.Data); err != nil {
			return err
		}
	}

	if err := writeU32(w, uint32(len(b.Env))); err != nil {
		return err
	}
	for _, e := range b.Env {
		if err := writeU16Bytes(w, []byte(e.Name)); err != nil {
			return err
		}
		if err := writeU32Bytes(w, e.Value); err != nil {
			return err
		}
	}

	if err := writeU32(w, uint32(len(b.Pointers))); err != nil {
		return err
	}
	for _, p := range b.Pointers {
		if err := writeU16Bytes(w, []byte(p.Name)); err != nil {
			return err
		}
		if err := writeU16Bytes(w, []byte(p.Path)); err != nil {
			return err
		}
	}

	return writeU32Bytes(w, b.Manifest)
}

// ReadResponse reads a response frame from r. On a bundle frame it returns the
// decoded Bundle, whose secret bytes are held in freshly allocated locked
// buffers the caller must Destroy. On an error frame it returns a non-nil error
// carrying the daemon's scrubbed reason. The client calls it after WriteRequest.
func ReadResponse(r io.Reader) (*Bundle, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("wire: read response header: %w", err)
	}
	if hdr[0] != ProtocolVersion {
		return nil, fmt.Errorf("wire: response protocol version %d, want %d", hdr[0], ProtocolVersion)
	}
	switch hdr[1] {
	case msgErrorResponse:
		reason, err := readU16Bytes(r)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("wire: daemon refused: %s", reason)
	case msgBundleResponse:
		return decodeBundle(r)
	default:
		return nil, fmt.Errorf("wire: response message type %d is not recognized", hdr[1])
	}
}

// decodeBundle reads a bundle body. It fails closed and Destroys any locked
// buffers already allocated if any field is malformed, so a partial or hostile
// frame never leaves live secret memory stranded.
func decodeBundle(r io.Reader) (b *Bundle, err error) {
	b = &Bundle{}
	defer func() {
		if err != nil {
			b.Destroy()
			b = nil
		}
	}()

	nFiles, err := readU32(r)
	if err != nil {
		return b, err
	}
	for i := uint32(0); i < nFiles; i++ {
		path, e := readU16String(r)
		if e != nil {
			return b, e
		}
		owner, e := readU16String(r)
		if e != nil {
			return b, e
		}
		mode, e := readU16String(r)
		if e != nil {
			return b, e
		}
		data, e := readU32Locked(r, b)
		if e != nil {
			return b, e
		}
		b.Files = append(b.Files, File{Path: path, Owner: owner, Mode: mode, Data: data})
	}

	nEnv, err := readU32(r)
	if err != nil {
		return b, err
	}
	for i := uint32(0); i < nEnv; i++ {
		name, e := readU16String(r)
		if e != nil {
			return b, e
		}
		val, e := readU32Locked(r, b)
		if e != nil {
			return b, e
		}
		b.Env = append(b.Env, EnvVar{Name: name, Value: val})
	}

	nPtr, err := readU32(r)
	if err != nil {
		return b, err
	}
	for i := uint32(0); i < nPtr; i++ {
		name, e := readU16String(r)
		if e != nil {
			return b, e
		}
		p, e := readU16String(r)
		if e != nil {
			return b, e
		}
		b.Pointers = append(b.Pointers, Pointer{Name: name, Path: p})
	}

	manifest, err := readU32Plain(r)
	if err != nil {
		return b, err
	}
	b.Manifest = manifest
	return b, nil
}

// --- integer and length-prefixed field helpers, all big-endian ---

func writeU16(w io.Writer, v uint32) error {
	if v > 0xffff {
		return fmt.Errorf("wire: field length %d exceeds u16", v)
	}
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], uint16(v))
	_, err := w.Write(buf[:])
	return err
}

func writeU32(w io.Writer, v uint32) error {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}

func writeU16Bytes(w io.Writer, p []byte) error {
	if err := writeU16(w, uint32(len(p))); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

func writeU32Bytes(w io.Writer, p []byte) error {
	if err := writeU32(w, uint32(len(p))); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

// writeStringMap writes a length-prefixed key/value map: a u16 count followed by
// that many (u16 key, u16 value) pairs. Keys are emitted in sorted order so the
// encoding is deterministic (stable golden tests, reproducible frames). The map
// carries only non-secret annotations.
func writeStringMap(w io.Writer, m map[string]string) error {
	if len(m) > 0xffff {
		return fmt.Errorf("wire: annotation count %d exceeds u16", len(m))
	}
	if err := writeU16(w, uint32(len(m))); err != nil {
		return err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := writeU16Bytes(w, []byte(k)); err != nil {
			return err
		}
		if err := writeU16Bytes(w, []byte(m[k])); err != nil {
			return err
		}
	}
	return nil
}

// readStringMap reads a map written by writeStringMap. The count and each field
// are bounded by the u16 caps, so a corrupt frame cannot drive an unbounded
// allocation. A zero count returns a non-nil empty map.
func readStringMap(r io.Reader) (map[string]string, error) {
	n, err := readU16(r)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, n)
	for i := 0; i < n; i++ {
		k, e := readU16String(r)
		if e != nil {
			return nil, e
		}
		v, e := readU16String(r)
		if e != nil {
			return nil, e
		}
		m[k] = v
	}
	return m, nil
}

func readU16(r io.Reader) (int, error) {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(buf[:])), nil
}

func readU32(r io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}

func readU16Bytes(r io.Reader) ([]byte, error) {
	n, err := readU16(r)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func readU16String(r io.Reader) (string, error) {
	p, err := readU16Bytes(r)
	if err != nil {
		return "", err
	}
	return string(p), nil
}

// readU32Plain reads a length-prefixed non-secret field (the manifest) onto the
// Go heap, which is acceptable because the manifest holds no secret value.
func readU32Plain(r io.Reader) ([]byte, error) {
	n, err := readU32(r)
	if err != nil {
		return nil, err
	}
	if n > maxField {
		return nil, fmt.Errorf("wire: field length %d exceeds cap %d", n, maxField)
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// readU32Locked reads a length-prefixed secret payload directly into a locked
// buffer tracked by b, so decoded plaintext lands in non-swappable memory that
// Bundle.Destroy zeroizes, not on Go's heap. A zero-length payload yields a
// non-nil empty slice and allocates no locked memory.
func readU32Locked(r io.Reader, b *Bundle) ([]byte, error) {
	n, err := readU32(r)
	if err != nil {
		return nil, err
	}
	if n > maxField {
		return nil, fmt.Errorf("wire: secret length %d exceeds cap %d", n, maxField)
	}
	if n == 0 {
		return []byte{}, nil
	}
	lb := memguard.NewBuffer(int(n))
	if _, err := io.ReadFull(r, lb.Bytes()); err != nil {
		lb.Destroy()
		return nil, err
	}
	return b.track(lb), nil
}
