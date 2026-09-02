// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

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

// createContainerState is the OCI state a runtime pipes to a createContainer
// hook: it runs inside the container's own mount namespace before pivot_root, so
// the pid is 0 (nothing to setns into) and the container root filesystem path is
// carried in the root field. This is the stage berm ships. Regression for the
// integration-found bug where the shipped createRuntime stage fired host-side
// before the container tmpfs existed and could not land the secret.
const createContainerState = `{
  "ociVersion": "1.0.2",
  "id": "3f1a2b9c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
  "status": "created",
  "pid": 0,
  "root": "/var/lib/containers/storage/overlay/abc123/merged",
  "bundle": "/var/lib/containers/storage/overlay-containers/3f1a2b9c/userdata",
  "annotations": { "berm.enable": "true" }
}`

func TestParseStateReadsRootField(t *testing.T) {
	s, err := ParseState(strings.NewReader(createContainerState))
	if err != nil {
		t.Fatalf("ParseState: %v", err)
	}
	if s.PID != 0 {
		t.Errorf("pid = %d, want 0 for a createContainer state", s.PID)
	}
	if s.Root != "/var/lib/containers/storage/overlay/abc123/merged" {
		t.Errorf("root = %q", s.Root)
	}
}

func TestContainerRootPrefersStateRoot(t *testing.T) {
	root, err := ContainerRoot(State{Root: "/some/merged", Bundle: "/ignored"})
	if err != nil {
		t.Fatalf("ContainerRoot: %v", err)
	}
	if root != "/some/merged" {
		t.Errorf("root = %q, want /some/merged", root)
	}
}

func TestContainerRootFallsBackToConfigJSON(t *testing.T) {
	// A runtime that omits state.root: resolve root.path from the bundle's
	// config.json. Cover both an absolute root.path and a relative one (resolved
	// against the bundle).
	for _, tc := range []struct {
		name     string
		rootPath string
		want     func(bundle string) string
	}{
		{"absolute", "/abs/merged", func(string) string { return "/abs/merged" }},
		{"relative", "rootfs", func(bundle string) string { return filepath.Join(bundle, "rootfs") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle := t.TempDir()
			cfg := `{"ociVersion":"1.0.2","root":{"path":"` + tc.rootPath + `"}}`
			if err := os.WriteFile(filepath.Join(bundle, "config.json"), []byte(cfg), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := ContainerRoot(State{Bundle: bundle})
			if err != nil {
				t.Fatalf("ContainerRoot: %v", err)
			}
			if got != tc.want(bundle) {
				t.Errorf("root = %q, want %q", got, tc.want(bundle))
			}
		})
	}
}

func TestContainerRootFailsClosed(t *testing.T) {
	// No root and no bundle: fail closed, never a guessed "/".
	if _, err := ContainerRoot(State{}); err == nil {
		t.Fatal("expected an error for a state with neither root nor bundle")
	}
	// A bundle with no config.json: fail closed.
	if _, err := ContainerRoot(State{Bundle: t.TempDir()}); err == nil {
		t.Fatal("expected an error for a bundle with no config.json")
	}
}

// TestWriteFilesUnderRootWithMergedRootPrefix proves the createContainer write
// path: the bundle's container-absolute paths land under the container rootfs
// prefix, exactly as the hook does when state.root is the merged rootfs. This is
// the byte-writing core the live nested-podman run exercises for real.
func TestWriteFilesUnderRootWithMergedRootPrefix(t *testing.T) {
	root, req := tmpfsTestDir(t)
	// Simulate a merged-rootfs prefix under the tmpfs dir.
	merged := filepath.Join(root, "merged")
	if err := os.MkdirAll(merged, 0o755); err != nil {
		t.Fatal(err)
	}
	b := knownFileBundle()
	defer b.Destroy()

	if err := WriteFilesUnderRoot(b, merged, wire.DefaultManifestPath, req); err != nil {
		t.Fatalf("WriteFilesUnderRoot: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(merged, "run/berm/pgpass"))
	if err != nil {
		t.Fatalf("read pgpass under merged root: %v", err)
	}
	if !bytes.Equal(got, []byte("p=ss w0rd!")) {
		t.Errorf("pgpass = %q", got)
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
