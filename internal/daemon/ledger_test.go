// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/delivery"
)

// recordOnePlan builds a one-file client plan for the named source/key and
// records its manifest into ledger, returning the manifest.
func recordOnePlan(t *testing.T, l *Ledger, opener delivery.Opener, container, service, source, key string) *delivery.Manifest {
	t.Helper()
	plan := delivery.Plan{
		Container: container,
		Service:   service,
		Mechanism: delivery.MechClient,
		Files: []delivery.FileTarget{{
			Name: "f", Source: source, Format: backend.FormatDotenv,
			Key: key, Path: "/run/berm/f", Owner: "0:0", Mode: "0400",
			PointerVar: key + "_FILE",
		}},
	}
	m, err := delivery.BuildManifest(plan, opener, time.Unix(1735689600, 0).UTC())
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	if err := l.RecordManifest(m, time.Unix(1735689600, 0).UTC()); err != nil {
		t.Fatalf("record manifest: %v", err)
	}
	return m
}

func TestLedgerDriftDetectionAndPersistence(t *testing.T) {
	const secretVal = "ledger-secret-value-999888"
	opener, cfg := realOpener(t,
		sopsSource{
			name:   "webapp",
			format: backend.FormatDotenv,
			dotenv: []kv{{"DB_PASSWORD", secretVal}},
		},
	)

	ledgerPath := filepath.Join(t.TempDir(), "ledger.json")
	l := NewLedger(ledgerPath)
	recordOnePlan(t, l, opener, "cid-webapp", "webapp", "webapp", "DB_PASSWORD")

	// No drift immediately after recording: the injected hash equals the current
	// ciphertext hash.
	drift, err := l.Drift(opener)
	if err != nil {
		t.Fatalf("drift: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("want no drift right after injection, got %+v", drift)
	}

	// Mutate the source ciphertext at rest (a rotation): its hash changes. Drift
	// compares ciphertext hashes only and never decrypts, so appending bytes is a
	// faithful stand-in for a re-encrypted source.
	cipherPath := cfg.Sources["webapp"].File
	f, err := os.OpenFile(cipherPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open ciphertext: %v", err)
	}
	if _, err := f.WriteString("\n# rotated\n"); err != nil {
		t.Fatalf("mutate ciphertext: %v", err)
	}
	f.Close()

	drift, err = l.Drift(opener)
	if err != nil {
		t.Fatalf("drift after rotation: %v", err)
	}
	if len(drift) != 1 {
		t.Fatalf("want 1 drift after rotation, got %+v", drift)
	}
	if drift[0].Container != "cid-webapp" || drift[0].Source != "webapp" {
		t.Errorf("drift = %+v, want cid-webapp/webapp", drift[0])
	}
	if drift[0].InjectedHash == drift[0].CurrentHash {
		t.Error("drift injected and current hash should differ after rotation")
	}

	// The ledger persisted and reloads with the same record across a restart.
	reloaded, err := LoadLedger(ledgerPath)
	if err != nil {
		t.Fatalf("reload ledger: %v", err)
	}
	rec, ok := reloaded.Record("cid-webapp")
	if !ok {
		t.Fatal("reloaded ledger lost the record")
	}
	if rec.Service != "webapp" {
		t.Errorf("reloaded service = %q, want webapp", rec.Service)
	}
	if _, ok := rec.Sources["webapp"]; !ok {
		t.Errorf("reloaded record missing the webapp source: %+v", rec.Sources)
	}

	// The reloaded ledger reports the same drift, so `berm stale` survives a
	// daemon restart.
	drift2, err := reloaded.Drift(opener)
	if err != nil {
		t.Fatalf("drift on reloaded: %v", err)
	}
	if len(drift2) != 1 {
		t.Errorf("reloaded ledger drift = %+v, want 1", drift2)
	}

	// The ledger file holds ciphertext hashes and names only, never a value.
	raw, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("read ledger file: %v", err)
	}
	assertNoValue(t, "ledger file", string(raw), secretVal)
}

func TestLedgerMissingSourceIsDrift(t *testing.T) {
	opener, cfg := realOpener(t,
		sopsSource{
			name:   "webapp",
			format: backend.FormatDotenv,
			dotenv: []kv{{"DB_PASSWORD", "will-be-deleted-1234"}},
		},
	)
	l := NewLedger(filepath.Join(t.TempDir(), "ledger.json"))
	recordOnePlan(t, l, opener, "cid-webapp", "webapp", "webapp", "DB_PASSWORD")

	// Delete the ciphertext entirely: the source vanished since injection.
	if err := os.Remove(cfg.Sources["webapp"].File); err != nil {
		t.Fatalf("remove ciphertext: %v", err)
	}

	drift, err := l.Drift(opener)
	if err != nil {
		t.Fatalf("drift: %v", err)
	}
	if len(drift) != 1 || !drift[0].Missing {
		t.Fatalf("want 1 missing-source drift, got %+v", drift)
	}
}

func TestLedgerForgetRemovesRecord(t *testing.T) {
	opener, _ := realOpener(t,
		sopsSource{
			name:   "webapp",
			format: backend.FormatDotenv,
			dotenv: []kv{{"DB_PASSWORD", "forget-me-secret-1234"}},
		},
	)
	path := filepath.Join(t.TempDir(), "ledger.json")
	l := NewLedger(path)
	recordOnePlan(t, l, opener, "cid-webapp", "webapp", "webapp", "DB_PASSWORD")

	if err := l.Forget("cid-webapp"); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if _, ok := l.Record("cid-webapp"); ok {
		t.Error("record survived Forget")
	}
	reloaded, err := LoadLedger(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := reloaded.Record("cid-webapp"); ok {
		t.Error("forgotten record came back after reload")
	}
}
