// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

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

// TestReconcilePopulatesCreatedButNotStartedVolumeContainer pins the integration
// finding that the volume-mode turnkey deploy deadlocked: compose creates the app
// up front and gates its start on a waiter that blocks on the manifest, but the
// daemon populated the volume only on the app's START event, which never fired.
// The reconcile pass must populate a volume-mode container that has been created
// (never started) so the manifest appears and the waiter clears. Found live via
// docker compose in the chunk-9a integration harness.
func TestReconcilePopulatesCreatedButNotStartedVolumeContainer(t *testing.T) {
	const secret = "reconcile-volume-secret-abcdef"
	opener, cfg := realOpener(t,
		sopsSource{
			name:   "webapp",
			format: backend.FormatDotenv,
			dotenv: []kv{{"DB_PASSWORD", secret}},
		},
	)

	rt := newFakeRuntime()
	// A CREATED, never-started volume-mode container: no start event is ever fed
	// to the loop, mirroring the compose app gated behind the manifest waiter.
	rt.add(runtime.Container{
		ID:      "cid-webapp",
		Name:    "/webapp",
		Service: "webapp",
		State:   "created",
		Labels: map[string]string{
			"berm.enable":           "true",
			"berm.delivery":         "volume",
			"berm.file.pgpass.from": "DB_PASSWORD",
		},
	})

	volRoot := tmpfsDir(t)
	// The operator mounts the app's shared volume into the daemon: its daemon-side
	// mount must already exist for the reconcile to write into it. volName is the
	// default berm-<service>.
	mountPath := filepath.Join(volRoot, "berm-webapp")
	if err := os.MkdirAll(mountPath, 0o755); err != nil {
		t.Fatalf("prepare mounted volume dir: %v", err)
	}

	d, err := New(Config{
		Runtime:           rt,
		Berm:              cfg,
		Opener:            opener,
		Sink:              &fakeSink{},
		VolumeMountRoot:   volRoot,
		LedgerPath:        filepath.Join(t.TempDir(), "ledger.json"),
		ReconcileInterval: -1, // drive reconcile manually, no background ticker
		Clock:             func() time.Time { return time.Unix(1735689600, 0).UTC() },
		Logger:            slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Before reconcile: no manifest, so the waiter would block forever.
	manifestPath := filepath.Join(mountPath, "manifest")
	if _, err := os.Stat(manifestPath); err == nil {
		t.Fatal("manifest present before reconcile: test setup is wrong")
	}

	// The reconcile populates the created-but-not-started container.
	d.reconcileVolumes(context.Background())

	filePath := filepath.Join(mountPath, "pgpass")
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("reconcile did not write the secret into the created container's volume: %v", err)
	}
	if string(data) != secret {
		t.Errorf("reconciled volume file = %q, want %q", data, secret)
	}
	if _, err := os.Stat(manifestPath); err != nil {
		t.Errorf("reconcile did not write the manifest (the waiter's ready signal): %v", err)
	}

	// Idempotent: a second reconcile is a no-op because the manifest (ready
	// signal) is now present. It must not error or re-alert.
	sink2 := &fakeSink{}
	d.sink = sink2
	d.reconcileVolumes(context.Background())
	if sink2.count() != 0 {
		t.Errorf("second reconcile alerted %d time(s), want 0 (already populated)", sink2.count())
	}
}
