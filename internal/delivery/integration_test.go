// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

//go:build integration

// This is the real crypto round-trip for the delivery layer. It runs ONLY under
// the "integration" build tag and ONLY where sops and age are on PATH, because
// it drives them for real: it generates an age keypair, sops-encrypts a dotenv
// and a binary fixture, then runs the client-fetch handler and the tmpfs writer
// end to end against a real SOPS/age backend behind a ConfigOpener, and
// byte-compares every delivered secret to the known plaintext. It reuses the
// chunk-3 harness pattern. Nothing here ships in a binary.
//
//	go test -tags integration -buildvcs=false ./internal/delivery/...
package delivery

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/config"
)

func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("integration harness needs %q on PATH: %v", name, err)
	}
}

func genAgeKey(t *testing.T, dir, name string) (keyPath, recipient string) {
	t.Helper()
	keyPath = filepath.Join(dir, name)
	cmd := exec.Command("age-keygen", "-o", keyPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("age-keygen: %v: %s", err, stderr.String())
	}
	f, err := os.Open(keyPath)
	if err != nil {
		t.Fatalf("open age key: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(strings.ToLower(line), "# public key:") {
			recipient = strings.TrimSpace(line[strings.IndexByte(line, ':')+1:])
		}
	}
	if recipient == "" {
		t.Fatal("could not parse age recipient")
	}
	return keyPath, recipient
}

func sopsEncrypt(t *testing.T, dir, recipient, sopsType string, plaintext []byte, outPath string) {
	t.Helper()
	rule := "creation_rules:\n  - path_regex: .*\n    age: " + recipient + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".sops.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}
	plainPath := filepath.Join(dir, "plain."+sopsType+".in")
	if err := os.WriteFile(plainPath, plaintext, 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	cmd := exec.Command("sops", "-e", "--input-type", sopsType, "--output-type", sopsType, plainPath)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sops encrypt: %v: %s", err, stderr.String())
	}
	if err := os.WriteFile(outPath, out.Bytes(), 0o600); err != nil {
		t.Fatalf("write ciphertext: %v", err)
	}
}

// TestClientFetchEndToEnd proves BuildBundle against a real SOPS/age backend:
// the bundle carries exactly this caller's secrets, byte-correct, and neither
// the manifest nor an error string ever holds a value.
func TestClientFetchEndToEnd(t *testing.T) {
	requireTool(t, "sops")
	requireTool(t, "age-keygen")

	dir := t.TempDir()
	keyPath, recipient := genAgeKey(t, dir, "default.key")

	// Known plaintext.
	dbPass := "p@ss w0rd = tricky"
	apiURL := "https://api.example/x?a=b&c=d"
	dotenvPlain := []byte("DB_PASSWORD=" + dbPass + "\nAPI_URL=" + apiURL + "\n")
	binPlain := []byte{0x00, 0x01, 0xff, 0xfe, 'T', 'L', 'S', '\n', 0x80}

	sopsEncrypt(t, dir, recipient, "dotenv", dotenvPlain, filepath.Join(dir, "webapp.sops.env"))
	sopsEncrypt(t, dir, recipient, "binary", binPlain, filepath.Join(dir, "webapp-tls.sops.bin"))

	cfg := &config.Config{
		AgeKeys: map[string]string{"default": keyPath},
		Sources: map[string]config.Source{
			"webapp":     {File: "webapp.sops.env", Format: "dotenv", AgeKey: "default"},
			"webapp-tls": {File: "webapp-tls.sops.bin", Format: "binary", AgeKey: "default"},
		},
	}
	cfg.Globals.SourcesRoot = dir

	opener := NewConfigOpener(cfg, backend.NewSOPSAge(cfg.AgeKeys))

	plan := Plan{
		Container: "c1", Service: "webapp", Mechanism: MechClient,
		Files: []FileTarget{
			{Name: "pgpass", Source: "webapp", Format: backend.FormatDotenv, Key: "DB_PASSWORD",
				Path: "/run/berm/pgpass", Owner: "1000:1000", Mode: "0400", PointerVar: "DB_PASSWORD_FILE"},
			{Name: "tls", Source: "webapp-tls", Format: backend.FormatBinary, Whole: true,
				Path: "/run/berm/tls.key", Owner: "1000:1000", Mode: "0440"},
		},
		Env: []EnvTarget{{All: true, Source: "webapp"}},
		Renders: []RenderTarget{
			{Kind: RenderDotenv, Source: "webapp", Path: "/run/berm/all.env", Owner: "0:0", Mode: "0400"},
		},
		EnvExposure: true,
	}

	b, err := BuildBundle(context.Background(), "webapp", plan, opener, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	defer b.Destroy()

	byPath := map[string][]byte{}
	for _, f := range b.Files {
		byPath[f.Path] = append([]byte(nil), f.Data...)
	}
	if !bytes.Equal(byPath["/run/berm/pgpass"], []byte(dbPass)) {
		t.Errorf("pgpass = %q, want %q", byPath["/run/berm/pgpass"], dbPass)
	}
	if !bytes.Equal(byPath["/run/berm/tls.key"], binPlain) {
		t.Errorf("tls = %v, want %v", byPath["/run/berm/tls.key"], binPlain)
	}
	wantRender := "DB_PASSWORD=" + dbPass + "\nAPI_URL=" + apiURL + "\n"
	if !bytes.Equal(byPath["/run/berm/all.env"], []byte(wantRender)) {
		t.Errorf("render = %q, want %q", byPath["/run/berm/all.env"], wantRender)
	}

	env := map[string][]byte{}
	for _, e := range b.Env {
		env[e.Name] = append([]byte(nil), e.Value...)
	}
	if !bytes.Equal(env["DB_PASSWORD"], []byte(dbPass)) || !bytes.Equal(env["API_URL"], []byte(apiURL)) {
		t.Errorf("env all wrong: DB_PASSWORD=%q API_URL=%q", env["DB_PASSWORD"], env["API_URL"])
	}

	// Manifest: real ciphertext hashes, no plaintext value.
	for _, v := range []string{dbPass, apiURL, string(binPlain)} {
		if len(v) >= 4 && bytes.Contains(b.Manifest, []byte(v)) {
			t.Fatalf("manifest leaked a value %q", v)
		}
	}
	if !bytes.Contains(b.Manifest, []byte("sha256:")) {
		t.Errorf("manifest missing a ciphertext hash:\n%s", b.Manifest)
	}
}

// TestWriteFileEndToEnd proves the streaming tmpfs writer against the real
// backend: it lands the decrypted secret at a tmpfs path, byte-correct.
func TestWriteFileEndToEnd(t *testing.T) {
	requireTool(t, "sops")
	requireTool(t, "age-keygen")

	dir := t.TempDir()
	keyPath, recipient := genAgeKey(t, dir, "default.key")
	binPlain := []byte{0x00, 0x01, 0xff, 0xfe, 'T', 'L', 'S', '\n', 0x80}
	sopsEncrypt(t, dir, recipient, "binary", binPlain, filepath.Join(dir, "webapp-tls.sops.bin"))

	cfg := &config.Config{
		AgeKeys: map[string]string{"default": keyPath},
		Sources: map[string]config.Source{
			"webapp-tls": {File: "webapp-tls.sops.bin", Format: "binary", AgeKey: "default"},
		},
	}
	cfg.Globals.SourcesRoot = dir
	opener := NewConfigOpener(cfg, backend.NewSOPSAge(cfg.AgeKeys))

	shm, req := tmpfsTestDir(t)
	dst := filepath.Join(shm, "server.key")
	ft := FileTarget{
		Name: "tls", Source: "webapp-tls", Format: backend.FormatBinary, Whole: true,
		Path: dst, Owner: "1000:1000", Mode: "0440",
	}
	if err := WriteFile(context.Background(), opener, ft, req); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, binPlain) {
		t.Errorf("written = %v, want %v", got, binPlain)
	}
}
