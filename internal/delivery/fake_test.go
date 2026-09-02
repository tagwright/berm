// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package delivery

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/tagwright/berm/internal/backend"
)

// fakeSource is one source's known plaintext for the unit tests, standing in for
// what the real SOPS/age backend would decrypt. cipher is a fixed stand-in hash
// (not a real digest of anything), chosen so it can never collide with a
// plaintext value in the no-leak assertions.
type fakeSource struct {
	format  backend.SourceFormat
	order   []string
	vals    map[string][]byte
	payload []byte
	cipher  string
}

// fakeOpener implements Opener over in-memory fakeSources, so the delivery core
// is exercised without driving sops. The integration test covers the real
// backend.
type fakeOpener struct {
	sources map[string]*fakeSource
}

func (o *fakeOpener) OpenSource(_ context.Context, source string) (backend.Opened, error) {
	s, ok := o.sources[source]
	if !ok {
		return nil, fmt.Errorf("fake: no such source %q", source)
	}
	return &fakeOpened{s: s}, nil
}

func (o *fakeOpener) SourceCipherHash(source string) (string, error) {
	s, ok := o.sources[source]
	if !ok {
		return "", fmt.Errorf("fake: no such source %q", source)
	}
	return s.cipher, nil
}

// fakeOpened implements backend.Opened over a fakeSource.
type fakeOpened struct {
	s *fakeSource
}

func (o *fakeOpened) Format() backend.SourceFormat { return o.s.format }

func (o *fakeOpened) Keys() ([]string, error) {
	if o.s.format != backend.FormatDotenv {
		return nil, backend.ErrWrongFormat
	}
	return append([]string(nil), o.s.order...), nil
}

func (o *fakeOpened) Value(key string) ([]byte, error) {
	if o.s.format != backend.FormatDotenv {
		return nil, backend.ErrWrongFormat
	}
	v, ok := o.s.vals[key]
	if !ok {
		return nil, backend.ErrNoSuchKey
	}
	return append([]byte(nil), v...), nil
}

func (o *fakeOpened) WriteValue(dst io.Writer, key string) (int64, error) {
	if o.s.format != backend.FormatDotenv {
		return 0, backend.ErrWrongFormat
	}
	v, ok := o.s.vals[key]
	if !ok {
		return 0, backend.ErrNoSuchKey
	}
	n, err := dst.Write(v)
	return int64(n), err
}

func (o *fakeOpened) Payload() ([]byte, error) {
	if o.s.format != backend.FormatBinary {
		return nil, backend.ErrWrongFormat
	}
	return append([]byte(nil), o.s.payload...), nil
}

func (o *fakeOpened) WritePayload(dst io.Writer) (int64, error) {
	if o.s.format != backend.FormatBinary {
		return 0, backend.ErrWrongFormat
	}
	n, err := dst.Write(o.s.payload)
	return int64(n), err
}

func (o *fakeOpened) Close() error { return nil }

var _ backend.Opened = (*fakeOpened)(nil)
var _ Opener = (*fakeOpener)(nil)

// testFixture is the known plaintext all delivery unit tests share. The values
// exercise edges: an '=', shell specials, spaces, and a binary payload with a
// NUL and high bytes.
func testFixture() *fakeOpener {
	return &fakeOpener{sources: map[string]*fakeSource{
		"webapp": {
			format: backend.FormatDotenv,
			order:  []string{"DB_PASSWORD", "API_URL", "SPECIAL"},
			vals: map[string][]byte{
				"DB_PASSWORD": []byte("p=ss w0rd!"),
				"API_URL":     []byte("https://api.example/x?a=b&c=d"),
				"SPECIAL":     []byte("a#b$c%d"),
			},
			cipher: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		},
		"webapp-tls": {
			format:  backend.FormatBinary,
			payload: []byte{0x00, 0x01, 0xff, 0xfe, 'K', 'E', 'Y', '\n', 0x80},
			cipher:  "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		},
	}}
}

// allPlaintextValues is every secret value the fixture holds, for no-leak
// assertions against manifests and error strings.
func allPlaintextValues() []string {
	f := testFixture()
	var out []string
	for _, s := range f.sources {
		for _, v := range s.vals {
			out = append(out, string(v))
		}
		if len(s.payload) > 0 {
			out = append(out, string(s.payload))
		}
	}
	return out
}

// assertNoLeak fails if b contains any known plaintext value. Short values (<4
// bytes) are skipped to avoid coincidental substring matches, matching the
// backend harness convention.
func assertNoLeak(t *testing.T, what string, b []byte) {
	t.Helper()
	for _, v := range allPlaintextValues() {
		if len(v) >= 4 && bytesContains(b, []byte(v)) {
			t.Fatalf("%s leaked a plaintext value %q", what, v)
		}
	}
}

func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return len(needle) == 0
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

// tmpfsTestDir mirrors the wire package helper: prefer /dev/shm so the tmpfs
// path is exercised, fall back with enforcement relaxed and a note.
func tmpfsTestDir(t *testing.T) (dir string, requireTmpfs bool) {
	t.Helper()
	if d, err := os.MkdirTemp("/dev/shm", "berm-deliv-*"); err == nil {
		t.Cleanup(func() { os.RemoveAll(d) })
		return d, true
	}
	t.Log("NOTE: /dev/shm unavailable; using a non-tmpfs temp dir with the tmpfs guarantee relaxed. Production requires tmpfs.")
	return t.TempDir(), false
}
