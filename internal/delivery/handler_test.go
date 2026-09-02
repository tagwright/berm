// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package delivery

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestBuildBundleClient(t *testing.T) {
	plan := fullClientPlan()
	b, err := BuildBundle(context.Background(), "webapp", plan, testFixture(), time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	defer b.Destroy()

	// Files: pgpass, tls, and the dotenv render, byte-correct.
	byPath := map[string][]byte{}
	for _, f := range b.Files {
		byPath[f.Path] = append([]byte(nil), f.Data...)
	}
	if !bytes.Equal(byPath["/run/berm/pgpass"], []byte("p=ss w0rd!")) {
		t.Errorf("pgpass = %q", byPath["/run/berm/pgpass"])
	}
	if !bytes.Equal(byPath["/run/berm/tls/server.key"], []byte{0x00, 0x01, 0xff, 0xfe, 'K', 'E', 'Y', '\n', 0x80}) {
		t.Errorf("tls = %v", byPath["/run/berm/tls/server.key"])
	}
	if !bytes.Equal(byPath["/run/berm/all.env"], []byte("DB_PASSWORD=p=ss w0rd!\nAPI_URL=https://api.example/x?a=b&c=d\nSPECIAL=a#b$c%d\n")) {
		t.Errorf("render = %q", byPath["/run/berm/all.env"])
	}

	// Pointer for the file delivery.
	if len(b.Pointers) != 1 || b.Pointers[0].Name != "DB_PASSWORD_FILE" || b.Pointers[0].Path != "/run/berm/pgpass" {
		t.Errorf("pointers = %+v", b.Pointers)
	}

	// Env: the renamed DB_PASSWORD plus all-expansion of the 3 keys => 4 entries.
	envByName := map[string][]byte{}
	for _, e := range b.Env {
		envByName[e.Name] = append([]byte(nil), e.Value...)
	}
	if len(b.Env) != 4 {
		var names []string
		for _, e := range b.Env {
			names = append(names, e.Name)
		}
		t.Errorf("env count = %d, want 4 (%v)", len(b.Env), names)
	}
	if !bytes.Equal(envByName["DB_PASSWORD"], []byte("p=ss w0rd!")) {
		t.Errorf("env DB_PASSWORD = %q", envByName["DB_PASSWORD"])
	}
	if !bytes.Equal(envByName["API_URL"], []byte("https://api.example/x?a=b&c=d")) {
		t.Errorf("env API_URL = %q", envByName["API_URL"])
	}

	// Manifest present, records names/paths/hashes, and never a value.
	if len(b.Manifest) == 0 {
		t.Fatal("manifest missing")
	}
	assertNoLeak(t, "bundle manifest", b.Manifest)
	m := string(b.Manifest)
	for _, want := range []string{"pgpass", "/run/berm/pgpass", "sha256:1111", "webapp-tls", "DB_PASSWORD_FILE"} {
		if !bytes.Contains(b.Manifest, []byte(want)) {
			t.Errorf("manifest missing %q; manifest=\n%s", want, m)
		}
	}
}

func TestBuildBundleEnvGateRefusedNonClient(t *testing.T) {
	plan := Plan{
		Service:   "webapp",
		Mechanism: MechHook,
		Env:       []EnvTarget{{Var: "X", Source: "webapp", Key: "DB_PASSWORD"}},
	}
	_, err := BuildBundle(context.Background(), "webapp", plan, testFixture(), time.Now())
	if !errors.Is(err, ErrEnvUnsupported) {
		t.Fatalf("BuildBundle env on hook = %v, want ErrEnvUnsupported", err)
	}
}

func TestBuildBundleScopeMismatch(t *testing.T) {
	plan := fullClientPlan() // Service: webapp
	_, err := BuildBundle(context.Background(), "intruder", plan, testFixture(), time.Now())
	if err == nil {
		t.Fatal("expected a scope-mismatch refusal")
	}
}
