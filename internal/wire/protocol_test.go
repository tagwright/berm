// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package wire

import (
	"bytes"
	"testing"
)

func TestBundleRoundTrip(t *testing.T) {
	src := &Bundle{
		Pointers: []Pointer{{Name: "POSTGRES_PASSWORD_FILE", Path: "/run/berm/pgpass"}},
		Manifest: []byte(`{"version":1}`),
	}
	f1 := src.AddSecret([]byte("file-one-plaintext"))
	f2 := src.AddSecret([]byte{0x00, 0xff, 0x10}) // binary bytes
	e1 := src.AddSecret([]byte("env-plaintext-value"))
	empty := src.AddSecret(nil) // present-but-empty secret
	src.Files = []File{
		{Path: "/run/berm/one", Owner: "1000:1000", Mode: "0400", Data: f1},
		{Path: "/run/berm/two", Owner: "0:0", Mode: "0440", Data: f2},
		{Path: "/run/berm/empty", Owner: "0:0", Mode: "0400", Data: empty},
	}
	src.Env = []EnvVar{{Name: "SECRET", Value: e1}}

	var buf bytes.Buffer
	if err := EncodeBundle(&buf, src); err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	src.Destroy()

	got, err := ReadResponse(&buf)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer got.Destroy()

	if len(got.Files) != 3 {
		t.Fatalf("files = %d, want 3", len(got.Files))
	}
	if got.Files[0].Path != "/run/berm/one" || got.Files[0].Owner != "1000:1000" || got.Files[0].Mode != "0400" {
		t.Errorf("file0 meta wrong: %+v", got.Files[0])
	}
	if !bytes.Equal(got.Files[0].Data, []byte("file-one-plaintext")) {
		t.Errorf("file0 data = %q", got.Files[0].Data)
	}
	if !bytes.Equal(got.Files[1].Data, []byte{0x00, 0xff, 0x10}) {
		t.Errorf("file1 data = %v", got.Files[1].Data)
	}
	if len(got.Files[2].Data) != 0 {
		t.Errorf("file2 empty data = %v", got.Files[2].Data)
	}
	if len(got.Env) != 1 || got.Env[0].Name != "SECRET" || !bytes.Equal(got.Env[0].Value, []byte("env-plaintext-value")) {
		t.Errorf("env wrong: %+v", got.Env)
	}
	if len(got.Pointers) != 1 || got.Pointers[0].Name != "POSTGRES_PASSWORD_FILE" || got.Pointers[0].Path != "/run/berm/pgpass" {
		t.Errorf("pointer wrong: %+v", got.Pointers)
	}
	if !bytes.Equal(got.Manifest, []byte(`{"version":1}`)) {
		t.Errorf("manifest = %q", got.Manifest)
	}
}

func TestErrorFrame(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteError(&buf, "source \"webapp\" is not granted"); err != nil {
		t.Fatalf("WriteError: %v", err)
	}
	_, err := ReadResponse(&buf)
	if err == nil {
		t.Fatal("expected an error from an error frame")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("not granted")) {
		t.Errorf("error frame reason lost: %v", err)
	}
}

func TestRequestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteRequest(&buf); err != nil {
		t.Fatalf("WriteRequest: %v", err)
	}
	if err := ReadRequest(&buf); err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
}

func TestVersionMismatchRejected(t *testing.T) {
	// A frame with a wrong version byte must be rejected, not misparsed.
	buf := bytes.NewReader([]byte{ProtocolVersion + 1, msgBundleResponse})
	if _, err := ReadResponse(buf); err == nil {
		t.Fatal("expected a version-mismatch error")
	}
}

func TestProtocolVersionIsTwo(t *testing.T) {
	// The hook-request addition bumped the protocol version to 2. This pins the
	// bump so a future change to the frame layout has to bump it again on
	// purpose.
	if ProtocolVersion != 2 {
		t.Fatalf("ProtocolVersion = %d, want 2 after the hook-request bump", ProtocolVersion)
	}
}

func TestHookRequestRoundTrip(t *testing.T) {
	const id = "3f1a2b9c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8"
	var buf bytes.Buffer
	if err := WriteHookRequest(&buf, id); err != nil {
		t.Fatalf("WriteHookRequest: %v", err)
	}

	// Whole-request reader.
	got, err := ReadHookRequest(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadHookRequest: %v", err)
	}
	if got != id {
		t.Errorf("hook container id = %q, want %q", got, id)
	}

	// Header-then-body dispatch, the path the daemon loop uses.
	r := bytes.NewReader(buf.Bytes())
	rt, err := ReadRequestHeader(r)
	if err != nil {
		t.Fatalf("ReadRequestHeader: %v", err)
	}
	if rt != RequestHook {
		t.Fatalf("request type = %v, want RequestHook", rt)
	}
	body, err := ReadHookBody(r)
	if err != nil {
		t.Fatalf("ReadHookBody: %v", err)
	}
	if body != id {
		t.Errorf("hook body id = %q, want %q", body, id)
	}
}

func TestWriteHookRequestRejectsEmptyID(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHookRequest(&buf, ""); err == nil {
		t.Fatal("expected an error writing a hook request with no container id")
	}
}

func TestRequestHeaderDispatch(t *testing.T) {
	// A fetch request classifies as RequestFetch; ReadRequest still accepts it,
	// and rejects a hook request as not-a-fetch.
	var fetchBuf bytes.Buffer
	if err := WriteRequest(&fetchBuf); err != nil {
		t.Fatal(err)
	}
	if rt, err := ReadRequestHeader(bytes.NewReader(fetchBuf.Bytes())); err != nil || rt != RequestFetch {
		t.Fatalf("fetch header = (%v, %v), want (RequestFetch, nil)", rt, err)
	}
	if err := ReadRequest(bytes.NewReader(fetchBuf.Bytes())); err != nil {
		t.Fatalf("ReadRequest(fetch) = %v, want nil", err)
	}

	var hookBuf bytes.Buffer
	if err := WriteHookRequest(&hookBuf, "abc"); err != nil {
		t.Fatal(err)
	}
	if err := ReadRequest(bytes.NewReader(hookBuf.Bytes())); err == nil {
		t.Fatal("ReadRequest must reject a hook request")
	}
}

func TestHookRequestVersionMismatchRejected(t *testing.T) {
	// A hook frame with a wrong version byte is rejected, not misparsed.
	buf := bytes.NewReader([]byte{ProtocolVersion + 1, msgHookRequest})
	if _, err := ReadRequestHeader(buf); err == nil {
		t.Fatal("expected a version-mismatch error on a hook header")
	}
}
