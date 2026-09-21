// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/delivery"
)

// TestHeartbeatRoundTripAndFreshness pins the write/read round trip and the
// freshness window healthz keys off: a beat inside staleAfter is fresh, one past
// it is stale, and a clock that has moved backward reads as just-written rather
// than spuriously stale.
func TestHeartbeatRoundTripAndFreshness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heartbeat")
	base := time.Unix(1735689600, 0).UTC()

	if err := WriteHeartbeat(path, base); err != nil {
		t.Fatalf("WriteHeartbeat: %v", err)
	}
	got, err := ReadHeartbeat(path)
	if err != nil {
		t.Fatalf("ReadHeartbeat: %v", err)
	}
	if !got.Equal(base) {
		t.Errorf("round trip = %v, want %v", got, base)
	}

	const staleAfter = 6 * time.Second
	cases := []struct {
		name      string
		now       time.Time
		wantFresh bool
		wantAge   time.Duration
	}{
		{"just written", base, true, 0},
		{"within threshold", base.Add(2 * time.Second), true, 2 * time.Second},
		{"exactly at threshold", base.Add(staleAfter), true, staleAfter},
		{"past threshold is stale", base.Add(10 * time.Second), false, 10 * time.Second},
		{"clock moved back clamps to zero", base.Add(-3 * time.Second), true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fresh, age, err := HeartbeatFresh(path, c.now, staleAfter)
			if err != nil {
				t.Fatalf("HeartbeatFresh: %v", err)
			}
			if fresh != c.wantFresh {
				t.Errorf("fresh = %v, want %v", fresh, c.wantFresh)
			}
			if age != c.wantAge {
				t.Errorf("age = %v, want %v", age, c.wantAge)
			}
		})
	}
}

// TestHeartbeatMissingIsNotExist pins that a missing heartbeat is reported as a
// not-exist error, which is how healthz tells "the daemon never wrote a beat"
// (daemon down or reconcile loop not running) from a merely stale one.
func TestHeartbeatMissingIsNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-written")
	fresh, _, err := HeartbeatFresh(path, time.Now(), time.Second)
	if err == nil {
		t.Fatal("expected an error for a missing heartbeat")
	}
	if !os.IsNotExist(err) {
		t.Errorf("missing heartbeat error = %v, want an os.IsNotExist error", err)
	}
	if fresh {
		t.Error("a missing heartbeat must not report fresh")
	}
}

// TestHeartbeatUnparseable pins that a corrupt heartbeat file is unhealthy (an
// error) rather than being mistaken for a valid or missing beat.
func TestHeartbeatUnparseable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt")
	if err := os.WriteFile(path, []byte("not-a-timestamp\n"), 0o644); err != nil {
		t.Fatalf("seed corrupt heartbeat: %v", err)
	}
	fresh, _, err := HeartbeatFresh(path, time.Now(), time.Second)
	if err == nil {
		t.Fatal("expected an error for an unparseable heartbeat")
	}
	if os.IsNotExist(err) {
		t.Errorf("unparseable heartbeat should not report not-exist: %v", err)
	}
	if fresh {
		t.Error("an unparseable heartbeat must not report fresh")
	}
}

// TestReconcileLoopWritesAndAdvancesHeartbeat proves the last requirement: a
// normally running daemon writes the heartbeat and keeps advancing it. It drives
// runReconcile with an empty runtime (a fast no-op reconcile pass) on a short
// interval, then confirms the beat appears, advances across passes, and reads as
// fresh through the same HeartbeatFresh healthz uses.
func TestReconcileLoopWritesAndAdvancesHeartbeat(t *testing.T) {
	rt := newFakeRuntime() // no containers: reconcileVolumes is a quick no-op pass
	cfg := &config.Config{Sources: map[string]config.Source{}}
	// A real, non-nil opener that the empty-list reconcile never actually calls.
	opener := delivery.NewConfigOpener(cfg, backend.NewSOPSAge(map[string]string{}))

	hbPath := filepath.Join(t.TempDir(), "heartbeat")
	d, err := New(Config{
		Runtime:           rt,
		Berm:              cfg,
		Opener:            opener,
		Sink:              &fakeSink{},
		LedgerPath:        filepath.Join(t.TempDir(), "ledger.json"),
		ReconcileInterval: 5 * time.Millisecond,
		HeartbeatPath:     hbPath,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		// Clock left nil so it is the real clock and successive beats differ.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.runReconcile(ctx)

	waitFor(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(hbPath)
		return statErr == nil
	}, "reconcile loop never wrote the heartbeat")

	first, err := ReadHeartbeat(hbPath)
	if err != nil {
		t.Fatalf("read first heartbeat: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		next, rerr := ReadHeartbeat(hbPath)
		return rerr == nil && next.After(first)
	}, "heartbeat did not advance across reconcile passes")

	// A running daemon reads healthy through the same path healthz uses.
	fresh, _, err := HeartbeatFresh(hbPath, time.Now(), DefaultHeartbeatStaleAfter)
	if err != nil {
		t.Fatalf("HeartbeatFresh on a running daemon: %v", err)
	}
	if !fresh {
		t.Error("a running daemon must read as fresh")
	}
}
