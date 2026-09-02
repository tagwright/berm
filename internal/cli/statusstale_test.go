// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/daemon"
)

func statusConfig() *config.Config {
	return &config.Config{
		Sources: map[string]config.Source{
			"webapp":    {File: "webapp.sops.env", Format: "dotenv"},
			"paperless": {File: "paperless.sops.env", Format: "dotenv"},
		},
		Defaults: config.Defaults{Delivery: "client"},
	}
}

func TestStatusRowsWarnAndFlagSticky(t *testing.T) {
	cfg := statusConfig()
	rt := newFakeRuntime()

	// Clean file-delivery container.
	rt.add(runtime.Container{
		ID: "cid-webapp", Name: "/webapp", Service: "webapp",
		Labels: map[string]string{
			"berm.enable":           "true",
			"berm.delivery":         "client",
			"berm.file.pgpass.from": "DB_PASSWORD",
		},
	})
	// Env-exposure container (env=all on its own owned source, acknowledged).
	rt.add(runtime.Container{
		ID: "cid-paper", Name: "/paperless", Service: "paperless",
		Labels: map[string]string{
			"berm.enable":          "true",
			"berm.delivery":        "client",
			"berm.env":             "all",
			"berm.env.acknowledge": "true",
		},
	})
	// Broken container: missing source, sticky.
	rt.add(runtime.Container{
		ID: "cid-broken", Name: "/broken", Service: "broken",
		Labels: map[string]string{
			"berm.enable":      "true",
			"berm.delivery":    "client",
			"berm.file.x.from": "nope/KEY",
		},
	})
	// Inert container: omitted.
	rt.add(runtime.Container{ID: "cid-plain", Name: "/plain", Service: "plain"})

	ledger := daemon.NewLedger(filepath.Join(t.TempDir(), "ledger.json"))
	hs := fakeHashSource{}

	var out bytes.Buffer
	if err := Status(context.Background(), &out, rt, cfg, hs, ledger); err != nil {
		t.Fatalf("status: %v", err)
	}
	got := out.String()

	for _, want := range []string{
		"webapp", "paperless", "broken",
		"file:/run/berm/pgpass",  // resolved delivery target
		"env:all(paperless)",     // env-all target summary
		"env exposure warnings:", // the honest warning section
		"/proc/<pid>/environ",
		"berm.env.acknowledge is affirmed",
		"validation errors (sticky, held until fixed):",
		"missing_source",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("status output missing %q\n---\n%s", want, got)
		}
	}
	// The broken row is flagged sticky in the table.
	if !strings.Contains(got, "ERROR missing_source (sticky)") {
		t.Errorf("broken row should carry the sticky flag:\n%s", got)
	}
	if strings.Contains(got, "cid-plain") {
		t.Errorf("inert container should be omitted:\n%s", got)
	}
}

// seedLedger writes a one-container ledger JSON to a temp file and loads it, so
// the stale query has a recorded injection to compare against. The recorded
// hash is a ciphertext hash, never a secret value.
func seedLedger(t *testing.T, container, service, source, hash string) *daemon.Ledger {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.json")
	body := `{
  "version": 1,
  "containers": {
    "` + container + `": {
      "service": "` + service + `",
      "mechanism": "client",
      "sources": {
        "` + source + `": {"cipher_hash": "` + hash + `", "injected_at": "2026-08-01T00:00:00Z"}
      },
      "updated_at": "2026-08-01T00:00:00Z"
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("seed ledger: %v", err)
	}
	l, err := daemon.LoadLedger(path)
	if err != nil {
		t.Fatalf("load seeded ledger: %v", err)
	}
	return l
}

func TestStaleReportsDrift(t *testing.T) {
	ledger := seedLedger(t, "cid-webapp", "webapp", "webapp", "sha256:OLD")
	// The source ciphertext on disk now hashes differently: drift.
	hs := fakeHashSource{"webapp": "sha256:NEW"}

	var out bytes.Buffer
	if err := Stale(&out, ledger, hs); err != nil {
		t.Fatalf("stale: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"1 drifted source(s)",
		"cid-webapp",
		"webapp",
		"changed",
		"docker compose up -d --no-deps",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("stale drift output missing %q\n---\n%s", want, got)
		}
	}
}

func TestStaleCleanWhenNoDrift(t *testing.T) {
	ledger := seedLedger(t, "cid-webapp", "webapp", "webapp", "sha256:OLD")
	// The source ciphertext on disk still matches: no drift.
	hs := fakeHashSource{"webapp": "sha256:OLD"}

	var out bytes.Buffer
	if err := Stale(&out, ledger, hs); err != nil {
		t.Fatalf("stale: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "No drift.") {
		t.Errorf("clean stale should report no drift:\n%s", got)
	}
}
