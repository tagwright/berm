// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/backend"
)

func TestControlLoopVolumePushAndLedger(t *testing.T) {
	const dbPass = "volume-mode-secret-abcdef"
	opener, cfg := realOpener(t,
		sopsSource{
			name:   "webapp",
			format: backend.FormatDotenv,
			dotenv: []kv{{"DB_PASSWORD", dbPass}},
		},
	)

	rt := newFakeRuntime()
	rt.add(runtime.Container{
		ID:      "cid-webapp",
		Name:    "/webapp",
		Service: "webapp",
		Labels: map[string]string{
			"berm.enable":           "true",
			"berm.delivery":         "volume",
			"berm.file.pgpass.from": "DB_PASSWORD",
		},
	})

	volRoot := tmpfsDir(t)
	d, err := New(Config{
		Runtime:         rt,
		Berm:            cfg,
		Opener:          opener,
		Sink:            &fakeSink{},
		VolumeMountRoot: volRoot,
		LedgerPath:      filepath.Join(t.TempDir(), "ledger.json"),
		Clock:           func() time.Time { return time.Unix(1735689600, 0).UTC() },
		Logger:          slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Feed a synthetic start event through the loop's event handler.
	d.handleEvent(context.Background(), runtime.Event{Type: runtime.EventStart, ID: "cid-webapp"})

	// ApplyVolume wrote the secret into the shared volume, rebased under the
	// daemon-side mount berm-<service>.
	filePath := filepath.Join(volRoot, "berm-webapp", "pgpass")
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("volume file not written: %v", err)
	}
	if string(data) != dbPass {
		t.Errorf("volume file data = %q, want %q", data, dbPass)
	}
	// The manifest landed as the ready signal.
	manifestPath := filepath.Join(volRoot, "berm-webapp", "manifest")
	if _, err := os.Stat(manifestPath); err != nil {
		t.Errorf("volume manifest (ready signal) not written: %v", err)
	}

	// The injection was recorded in the ledger with the source ciphertext hash.
	rec, ok := d.ledger.Record("cid-webapp")
	if !ok {
		t.Fatal("ledger did not record the volume injection")
	}
	if rec.Mechanism != "volume" {
		t.Errorf("ledger mechanism = %q, want volume", rec.Mechanism)
	}
	inj, ok := rec.Sources["webapp"]
	if !ok {
		t.Fatalf("ledger record missing the webapp source: %+v", rec.Sources)
	}
	if inj.CipherHash == "" {
		t.Error("ledger recorded an empty ciphertext hash")
	}
}

func TestControlLoopClientModeExpectsFetch(t *testing.T) {
	opener, cfg := realOpener(t,
		sopsSource{
			name:   "webapp",
			format: backend.FormatDotenv,
			dotenv: []kv{{"DB_PASSWORD", "client-mode-secret-1234"}},
		},
	)
	rt := newFakeRuntime()
	rt.add(runtime.Container{
		ID:      "cid-webapp",
		Name:    "/webapp",
		Service: "webapp",
		Labels: map[string]string{
			"berm.enable":           "true",
			"berm.delivery":         "client",
			"berm.file.pgpass.from": "DB_PASSWORD",
		},
	})

	cfg.Globals.ClientTimeout = 50 * time.Millisecond
	sink := &fakeSink{}
	d, err := New(Config{
		Runtime:    rt,
		Berm:       cfg,
		Opener:     opener,
		Sink:       sink,
		LedgerPath: filepath.Join(t.TempDir(), "ledger.json"),
		Logger:     slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A client-mode start registers a fetch expectation. With no fetch, the
	// timeout fires an alert naming the container.
	d.handleEvent(context.Background(), runtime.Event{Type: runtime.EventStart, ID: "cid-webapp"})
	waitFor(t, time.Second, func() bool { return sink.count() > 0 }, "client-mode start did not alert on missing fetch")
	if got := sink.all()[0]; got.Fields["container"] != "cid-webapp" {
		t.Errorf("timeout alert container = %q, want cid-webapp", got.Fields["container"])
	}
	d.tracker.stop()
}
