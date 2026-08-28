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
