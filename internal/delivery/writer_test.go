// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package delivery

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/config"
)

func statOwnerMode(t *testing.T, path string) (uid, gid uint32, mode os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no syscall.Stat_t for %q", path)
	}
	return st.Uid, st.Gid, fi.Mode().Perm()
}

func TestWriteFileDotenvKey(t *testing.T) {
	dir, req := tmpfsTestDir(t)
	path := filepath.Join(dir, "pgpass")
	ft := FileTarget{
		Name: "pgpass", Source: "webapp", Format: backend.FormatDotenv,
		Key: "DB_PASSWORD", Path: path, Owner: "1000:1000", Mode: "0400",
		PointerVar: "DB_PASSWORD_FILE",
	}
	if err := WriteFile(context.Background(), testFixture(), ft, req); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, []byte("p=ss w0rd!")) {
		t.Errorf("content = %q", got)
	}
	uid, gid, mode := statOwnerMode(t, path)
	if uid != 1000 || gid != 1000 {
		t.Errorf("owner = %d:%d, want 1000:1000", uid, gid)
	}
	if mode != 0o400 {
		t.Errorf("mode = %o, want 0400", mode)
	}
}

func TestWriteFileBinaryWhole(t *testing.T) {
	dir, req := tmpfsTestDir(t)
	path := filepath.Join(dir, "tls", "server.key")
	ft := FileTarget{
		Name: "tls-key", Source: "webapp-tls", Format: backend.FormatBinary,
		Whole: true, Path: path, Owner: "1000:1000", Mode: "0440",
	}
	if err := WriteFile(context.Background(), testFixture(), ft, req); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, _ := os.ReadFile(path)
	want := []byte{0x00, 0x01, 0xff, 0xfe, 'K', 'E', 'Y', '\n', 0x80}
	if !bytes.Equal(got, want) {
		t.Errorf("content = %v, want %v", got, want)
	}
	_, _, mode := statOwnerMode(t, path)
	if mode != 0o440 {
		t.Errorf("mode = %o, want 0440", mode)
	}
}

func TestWriteRenderDotenv(t *testing.T) {
	dir, req := tmpfsTestDir(t)
	path := filepath.Join(dir, "env")
	rt := RenderTarget{Kind: RenderDotenv, Source: "webapp", Path: path, Owner: "0:0", Mode: "0400"}
	if err := WriteRender(context.Background(), testFixture(), rt, req); err != nil {
		t.Fatalf("WriteRender dotenv: %v", err)
	}
	got, _ := os.ReadFile(path)
	// Order follows the source's key order.
	want := "DB_PASSWORD=p=ss w0rd!\nAPI_URL=https://api.example/x?a=b&c=d\nSPECIAL=a#b$c%d\n"
	if string(got) != want {
		t.Errorf("render =\n%q\nwant\n%q", got, want)
	}
}

func TestWriteRenderEnvdir(t *testing.T) {
	dir, req := tmpfsTestDir(t)
	root := filepath.Join(dir, "envdir")
	rt := RenderTarget{Kind: RenderEnvdir, Source: "webapp", Path: root, Owner: "1000:1000", Mode: "0400"}
	if err := WriteRender(context.Background(), testFixture(), rt, req); err != nil {
		t.Fatalf("WriteRender envdir: %v", err)
	}
	for k, v := range map[string]string{
		"DB_PASSWORD": "p=ss w0rd!",
		"API_URL":     "https://api.example/x?a=b&c=d",
		"SPECIAL":     "a#b$c%d",
	} {
		got, err := os.ReadFile(filepath.Join(root, k))
		if err != nil {
			t.Fatalf("read envdir/%s: %v", k, err)
		}
		if string(got) != v {
			t.Errorf("envdir/%s = %q, want %q", k, got, v)
		}
		uid, _, mode := statOwnerMode(t, filepath.Join(root, k))
		if uid != 1000 || mode != 0o400 {
			t.Errorf("envdir/%s owner/mode = %d/%o", k, uid, mode)
		}
	}
}

// fullClientPlan is a client-mode plan exercising a file with a pointer, a
// binary whole file, both env forms, and both render shapes.
func fullClientPlan() Plan {
	return Plan{
		Container: "abc123",
		Service:   "webapp",
		Mechanism: MechClient,
		Files: []FileTarget{
			{Name: "pgpass", Source: "webapp", Format: backend.FormatDotenv, Key: "DB_PASSWORD",
				Path: "/run/berm/pgpass", Owner: "1000:1000", Mode: "0400", PointerVar: "DB_PASSWORD_FILE"},
			{Name: "tls", Source: "webapp-tls", Format: backend.FormatBinary, Whole: true,
				Path: "/run/berm/tls/server.key", Owner: "1000:1000", Mode: "0440"},
		},
		Env: []EnvTarget{
			{Var: "DB_PASSWORD", Source: "webapp", Key: "DB_PASSWORD"},
			{All: true, Source: "webapp"},
		},
		Renders: []RenderTarget{
			{Kind: RenderDotenv, Source: "webapp", Path: "/run/berm/all.env", Owner: "0:0", Mode: "0400"},
		},
		EnvExposure: true,
	}
}

func TestManifestNoValues(t *testing.T) {
	plan := fullClientPlan()
	m, err := BuildManifest(plan, testFixture(), time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	data, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	assertNoLeak(t, "manifest", data)
	// Cipher hashes recorded per source.
	if !bytes.Contains(data, []byte("sha256:1111")) || !bytes.Contains(data, []byte("sha256:2222")) {
		t.Errorf("manifest missing cipher hashes:\n%s", data)
	}
}

func TestConfigOpenerHashAndUnknownSource(t *testing.T) {
	// The config-backed opener hashes ciphertext at rest and errors on an unknown
	// source. The real decrypt path is covered by the integration test.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "webapp.sops.env"), []byte("ciphertext-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Sources: map[string]config.Source{
			"webapp": {File: "webapp.sops.env", Format: "dotenv"},
		},
	}
	cfg.Globals.SourcesRoot = dir
	op := NewConfigOpener(cfg, nil)

	h, err := op.SourceCipherHash("webapp")
	if err != nil {
		t.Fatalf("SourceCipherHash: %v", err)
	}
	if len(h) != len("sha256:")+64 || h[:7] != "sha256:" {
		t.Errorf("hash shape = %q", h)
	}
	if _, err := op.SourceCipherHash("nope"); err == nil {
		t.Error("expected error for unknown source")
	}
}
