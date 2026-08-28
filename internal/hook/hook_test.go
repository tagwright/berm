// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tagwright/berm/internal/wire"
)

// sampleState is a realistic OCI runtime State document, the JSON a runtime
// pipes to a pre-start hook on stdin, shaped after the OCI runtime-spec State
// schema: ociVersion, id, status, pid, bundle, and annotations (which carry the
// compose labels in a Podman deployment).
const sampleState = `{
  "ociVersion": "1.0.2",
  "id": "3f1a2b9c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
  "status": "created",
  "pid": 4422,
  "bundle": "/run/containers/storage/overlay-containers/3f1a2b9c/userdata",
  "annotations": {
    "io.container.manager": "libpod",
    "com.docker.compose.project": "myproj",
    "com.docker.compose.service": "webapp",
    "berm.enable": "true"
  }
}`

func TestParseStateExtractsIDAndPID(t *testing.T) {
	s, err := ParseState(strings.NewReader(sampleState))
	if err != nil {
		t.Fatalf("ParseState: %v", err)
	}
	const wantID = "3f1a2b9c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8"
	if s.ID != wantID {
		t.Errorf("id = %q, want %q", s.ID, wantID)
	}
	if s.PID != 4422 {
		t.Errorf("pid = %d, want 4422", s.PID)
	}
	if s.Status != "created" {
		t.Errorf("status = %q, want created", s.Status)
	}
	if s.Annotations["com.docker.compose.service"] != "webapp" {
		t.Errorf("service annotation = %q", s.Annotations["com.docker.compose.service"])
	}
}

func TestParseStateRejectsNoID(t *testing.T) {
	if _, err := ParseState(strings.NewReader(`{"ociVersion":"1.0.2","pid":10}`)); err == nil {
		t.Fatal("expected an error for a state with no container id")
	}
	if _, err := ParseState(strings.NewReader(`not json`)); err == nil {
		t.Fatal("expected an error for non-JSON state")
	}
}

// tmpfsTestDir prefers /dev/shm so the tmpfs write path is exercised, else a
// normal temp dir with enforcement relaxed.
func tmpfsTestDir(t *testing.T) (dir string, requireTmpfs bool) {
	t.Helper()
	if d, err := os.MkdirTemp("/dev/shm", "berm-hook-*"); err == nil {
		t.Cleanup(func() { os.RemoveAll(d) })
		return d, true
	}
	t.Log("NOTE: /dev/shm unavailable; using a non-tmpfs temp dir, tmpfs guarantee relaxed. Production requires tmpfs.")
	return t.TempDir(), false
}

// knownFileBundle builds a hook-style bundle: files and a manifest, no env
// (hook mode is files only). Paths are container-absolute; the test writes them
// under a temp-dir root, standing in for the container mount ns.
func knownFileBundle() *wire.Bundle {
	b := &wire.Bundle{}
	b.Files = []wire.File{
		{Path: "/run/berm/pgpass", Owner: "1000:1000", Mode: "0400", Data: b.AddSecret([]byte("p=ss w0rd!"))},
		{Path: "/run/berm/tls/server.key", Owner: "0:0", Mode: "0440", Data: b.AddSecret([]byte{0x00, 0xff, 'K'})},
	}
	b.Manifest = []byte(`{"version":1,"service":"webapp"}`)
	return b
}

func TestWriteFilesUnderRoot(t *testing.T) {
	root, req := tmpfsTestDir(t)
	b := knownFileBundle()
	defer b.Destroy()

	if err := WriteFilesUnderRoot(b, root, wire.DefaultManifestPath, req); err != nil {
		t.Fatalf("WriteFilesUnderRoot: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "run/berm/pgpass"))
	if err != nil {
		t.Fatalf("read pgpass: %v", err)
	}
	if !bytes.Equal(got, []byte("p=ss w0rd!")) {
		t.Errorf("pgpass = %q", got)
	}
	fi, _ := os.Stat(filepath.Join(root, "run/berm/pgpass"))
	if fi.Mode().Perm() != 0o400 {
		t.Errorf("pgpass mode = %o, want 0400", fi.Mode().Perm())
	}

	got2, err := os.ReadFile(filepath.Join(root, "run/berm/tls/server.key"))
	if err != nil {
		t.Fatalf("read tls: %v", err)
	}
	if !bytes.Equal(got2, []byte{0x00, 0xff, 'K'}) {
		t.Errorf("tls = %v", got2)
	}

	man, err := os.ReadFile(filepath.Join(root, wire.DefaultManifestPath))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !bytes.Contains(man, []byte(`"service":"webapp"`)) {
		t.Errorf("manifest = %q", man)
	}
}

// TestWriteIntoMountNSFailsClosed proves the setns path fails closed on a bad
// pid rather than writing anywhere. It does NOT fake a live-Podman result: the
// real setns-into-a-live-container write is proven in the nested-podman
// integration phase.
func TestWriteIntoMountNSFailsClosed(t *testing.T) {
	b := knownFileBundle()
	defer b.Destroy()

	if err := WriteIntoMountNS(b, 0, wire.DefaultManifestPath, true); err == nil {
		t.Fatal("expected a refusal for a non-positive pid")
	}
	// A pid with no /proc/<pid>/ns/mnt (an implausibly high pid) must fail at the
	// namespace open, not proceed to write.
	if err := WriteIntoMountNS(b, 2147480000, wire.DefaultManifestPath, true); err == nil {
		t.Fatal("expected a failure opening a nonexistent mount namespace")
	}
}
