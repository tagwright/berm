// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/backend"
)

func TestStatusReportsEnabledContainers(t *testing.T) {
	opener, cfg := realOpener(t,
		sopsSource{
			name:   "webapp",
			format: backend.FormatDotenv,
			dotenv: []kv{{"DB_PASSWORD", "status-secret-1234"}},
		},
	)

	rt := newFakeRuntime()
	// A berm-enabled client container.
	rt.add(runtime.Container{
		ID: "cid-webapp", Name: "/webapp", Service: "webapp",
		Labels: map[string]string{
			"berm.enable":           "true",
			"berm.delivery":         "client",
			"berm.file.pgpass.from": "DB_PASSWORD",
		},
	})
	// A non-berm container: excluded from the report.
	rt.add(runtime.Container{ID: "cid-plain", Name: "/plain", Service: "plain"})

	l := NewLedger(filepath.Join(t.TempDir(), "ledger.json"))
	recordOnePlan(t, l, opener, "cid-webapp", "webapp", "webapp", "DB_PASSWORD")

	rows, err := Status(context.Background(), rt, cfg, opener, l)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 status row, got %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Service != "webapp" || r.Mechanism != "client" {
		t.Errorf("row = %+v, want webapp/client", r)
	}
	if !r.Injected {
		t.Error("row should be marked injected")
	}
	if r.ErrorClass != "" {
		t.Errorf("clean container should have no error, got %q", r.ErrorClass)
	}
}

func TestStatusReportsValidationError(t *testing.T) {
	opener, cfg := realOpener(t,
		sopsSource{
			name:   "webapp",
			format: backend.FormatDotenv,
			dotenv: []kv{{"DB_PASSWORD", "status-err-secret-1234"}},
		},
	)
	rt := newFakeRuntime()
	rt.add(runtime.Container{
		ID: "cid-webapp", Name: "/webapp", Service: "webapp",
		Labels: map[string]string{
			"berm.enable":      "true",
			"berm.delivery":    "client",
			"berm.file.x.from": "nope/KEY", // missing source
		},
	})

	l := NewLedger(filepath.Join(t.TempDir(), "ledger.json"))
	rows, err := Status(context.Background(), rt, cfg, opener, l)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].ErrorClass != "missing_source" {
		t.Errorf("error class = %q, want missing_source", rows[0].ErrorClass)
	}
	if !rows[0].Sticky {
		t.Error("a missing source is sticky")
	}
}
