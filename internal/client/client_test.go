// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package client

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tagwright/berm/internal/wire"
)

// tmpfsTestDir prefers /dev/shm so the tmpfs apply path is exercised, else a
// normal temp dir with enforcement relaxed.
func tmpfsTestDir(t *testing.T) (dir string, requireTmpfs bool) {
	t.Helper()
	if d, err := os.MkdirTemp("/dev/shm", "berm-client-*"); err == nil {
		t.Cleanup(func() { os.RemoveAll(d) })
		return d, true
	}
	t.Log("NOTE: /dev/shm unavailable; using a non-tmpfs temp dir, tmpfs guarantee relaxed. Production requires tmpfs.")
	return t.TempDir(), false
}

// serveOnce listens on a unix socket at sockPath and serves one connection with
// a bundle built by build. It mimics the daemon side: ReadRequest, EncodeBundle,
// Destroy. It returns once it has served (or failed) one connection.
func serveOnce(t *testing.T, sockPath string, build func() *wire.Bundle) {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if err := wire.ReadRequest(conn); err != nil {
			return
		}
		b := build()
		_ = wire.EncodeBundle(conn, b)
		b.Destroy()
	}()
}

// knownBundle builds a bundle whose file paths sit under dir, so the test can
// apply it without touching /run.
func knownBundle(dir string) *wire.Bundle {
	b := &wire.Bundle{}
	b.Files = []wire.File{
		{Path: filepath.Join(dir, "pgpass"), Owner: "1000:1000", Mode: "0400", Data: b.AddSecret([]byte("p=ss w0rd!"))},
		{Path: filepath.Join(dir, "tls.key"), Owner: "0:0", Mode: "0440", Data: b.AddSecret([]byte{0x00, 0xff, 'K'})},
	}
	b.Env = []wire.EnvVar{{Name: "DB_PASSWORD", Value: b.AddSecret([]byte("p=ss w0rd!"))}}
	b.Pointers = []wire.Pointer{{Name: "DB_PASSWORD_FILE", Path: filepath.Join(dir, "pgpass")}}
	b.Manifest = []byte(`{"version":1,"service":"webapp"}`)
	return b
}

func TestFetchAndApply(t *testing.T) {
	dir, req := tmpfsTestDir(t)
	sockPath := filepath.Join(dir, "berm.sock")
	serveOnce(t, sockPath, func() *wire.Bundle { return knownBundle(dir) })

	b, err := Fetch(context.Background(), sockPath, 5*time.Second)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer b.Destroy()

	// Bundle bytes correct off the wire.
	if !bytes.Equal(b.Files[0].Data, []byte("p=ss w0rd!")) {
		t.Errorf("file0 = %q", b.Files[0].Data)
	}
	if !bytes.Equal(b.Files[1].Data, []byte{0x00, 0xff, 'K'}) {
		t.Errorf("file1 = %v", b.Files[1].Data)
	}

	// Apply writes files to tmpfs with owner/mode, and the manifest.
	manPath := filepath.Join(dir, "manifest")
	if err := ApplyFiles(b, manPath, req); err != nil {
		t.Fatalf("ApplyFiles: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "pgpass"))
	if !bytes.Equal(got, []byte("p=ss w0rd!")) {
		t.Errorf("applied pgpass = %q", got)
	}
	fi, _ := os.Stat(filepath.Join(dir, "pgpass"))
	if fi.Mode().Perm() != 0o400 {
		t.Errorf("pgpass mode = %o", fi.Mode().Perm())
	}
	man, err := os.ReadFile(manPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !bytes.Contains(man, []byte(`"service":"webapp"`)) {
		t.Errorf("manifest = %q", man)
	}
}

func TestEnvForFoldsSecretsAndPointers(t *testing.T) {
	dir := t.TempDir()
	b := knownBundle(dir)
	defer b.Destroy()

	base := []string{"PATH=/usr/bin", "HOME=/root", "DB_PASSWORD=stale"}
	env := EnvFor(base, b)

	m := map[string]string{}
	for _, kv := range env {
		if i := indexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	if m["PATH"] != "/usr/bin" || m["HOME"] != "/root" {
		t.Errorf("base env lost: %v", m)
	}
	// The secret env value replaces the stale base value, not duplicates it.
	if m["DB_PASSWORD"] != "p=ss w0rd!" {
		t.Errorf("DB_PASSWORD = %q, want the secret value", m["DB_PASSWORD"])
	}
	count := 0
	for _, kv := range env {
		if len(kv) >= len("DB_PASSWORD=") && kv[:len("DB_PASSWORD=")] == "DB_PASSWORD=" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("DB_PASSWORD appears %d times, want 1 (no duplicate)", count)
	}
	// The non-secret pointer is set.
	if m["DB_PASSWORD_FILE"] != filepath.Join(dir, "pgpass") {
		t.Errorf("pointer = %q", m["DB_PASSWORD_FILE"])
	}
}

func TestFetchTimeoutNoServer(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "absent.sock")
	_, err := Fetch(context.Background(), sockPath, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected a connect error when no daemon is listening")
	}
}

func TestLookPath(t *testing.T) {
	// An absolute path that exists resolves to itself.
	if p, err := lookPath("/bin/sh"); err != nil || p != "/bin/sh" {
		// /bin/sh may be a symlink but must exist in the golang image.
		if _, statErr := os.Stat("/bin/sh"); statErr == nil {
			t.Errorf("lookPath(/bin/sh) = %q, %v", p, err)
		}
	}
	if _, err := lookPath("definitely-not-a-real-command-xyz"); err == nil {
		t.Error("expected lookPath to fail for a missing command")
	}
}

func TestEnvForStableOrder(t *testing.T) {
	dir := t.TempDir()
	b := knownBundle(dir)
	defer b.Destroy()
	env := EnvFor([]string{"A=1", "B=2"}, b)
	// Base entries keep their relative order ahead of the added ones.
	var names []string
	for _, kv := range env {
		names = append(names, kv[:indexByte(kv, '=')])
	}
	if len(names) < 2 || names[0] != "A" || names[1] != "B" {
		t.Errorf("base order not preserved: %v", names)
	}
}
