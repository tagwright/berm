// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tagwright/core/runtime"
	"github.com/tagwright/core/runtime/runtimetest"

	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/delivery"
)

// The daemon's three runtime touch points (Watch, List, Inspect) each handle a
// runtime fault by logging it and taking the safe path (the watch reconnects,
// the reconcile retries next tick, a start is skipped), never by silently
// swallowing it or pushing a secret to a container it could not identify. That
// log-and-continue is the intended, resilient behavior (#604), so these tests
// lock it in: each injects a fault on one runtime call and asserts the daemon
// surfaces it rather than dropping it on the floor.
//
// The faults are injected through the SHARED fake's per-operation knobs
// (rt.Faults.List / .Inspect and rt.Fail for the watch stream), which is the
// Level 2 fault-injection the Testing Standard requires (task #549/#550): a
// happy-path fake does not count, so every runtime fault the daemon's code path
// relies on gets a surfacing test.
//
// Two layers are covered. The first three tests drive the touch-point methods
// directly on a minimal Daemon, because those paths dereference only the runtime
// and the logger, so a direct call runs everywhere (no sops/age on PATH needed).
// The Run* tests then drive the SAME faults through the real production
// entrypoint (the Run seam) end to end, proving the wired daemon surfaces them
// and stays alive.

// faultDaemon builds a Daemon wired to just the runtime and a buffer-backed
// logger, which is all the runtime-fault paths under test dereference. The
// syncBuffer (defined in server_test.go) is concurrency-safe, which watchOnce
// needs since it logs from inside its own select loop.
func faultDaemon(rt runtime.Runtime) (*Daemon, *syncBuffer) {
	buf := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &Daemon{rt: rt, log: log}, buf
}

func TestWatchOnce_RuntimeWatchErrorSurfaces(t *testing.T) {
	rt := newFakeRuntime()
	d, buf := faultDaemon(rt)

	injected := errors.New("watch stream boom")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() { defer close(done); d.watchOnce(ctx) }()

	// Deliver the fault on the watch error channel, the way a real adapter
	// reports the socket dropping mid-stream. watchOnce must log it, not swallow
	// it. Cancelling the context is what unwinds the loop deterministically,
	// avoiding a race between draining the error and observing a closed stream.
	rt.Fail(injected)

	waitFor(t, 2*time.Second,
		func() bool { return strings.Contains(buf.String(), "watch stream boom") },
		"a watch-stream error was not logged (silently swallowed)")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchOnce did not return after ctx cancel")
	}

	got := buf.String()
	if !strings.Contains(got, "runtime watch error") {
		t.Errorf("a watch-stream error was not logged under the expected key; log =\n%s", got)
	}
	if !strings.Contains(got, "watch stream boom") {
		t.Errorf("the logged watch error did not carry its injected cause; log =\n%s", got)
	}
}

func TestReconcileVolumes_ListErrorSurfaces(t *testing.T) {
	rt := newFakeRuntime()
	rt.Faults.List = errors.New("list boom")
	d, buf := faultDaemon(rt)

	// A List failure here must not proceed to resolve or push anything; it logs
	// and returns so the next reconcile tick retries. reconcileVolumes returning
	// cleanly (no panic) plus the logged fault is the whole contract.
	d.reconcileVolumes(context.Background())

	got := buf.String()
	if !strings.Contains(got, "reconcile list failed") {
		t.Errorf("a reconcile List error was not logged (silently swallowed); log =\n%s", got)
	}
	if !strings.Contains(got, "list boom") {
		t.Errorf("the logged reconcile error did not carry its injected cause; log =\n%s", got)
	}
}

func TestHandleStart_InspectErrorSurfaces(t *testing.T) {
	rt := newFakeRuntime()
	rt.Faults.Inspect = errors.New("inspect boom")
	d, buf := faultDaemon(rt)

	// A failed inspect on a start event means the daemon cannot resolve the
	// container's plan, so it logs and skips rather than pushing a secret to a
	// container it could not identify.
	d.handleStart(context.Background(), "cid-unknowable")

	got := buf.String()
	if !strings.Contains(got, "inspect started container failed") {
		t.Errorf("an Inspect error on start was not logged (silently swallowed); log =\n%s", got)
	}
	if !strings.Contains(got, "inspect boom") {
		t.Errorf("the logged inspect error did not carry its injected cause; log =\n%s", got)
	}
}

// seamDaemon builds the collaborators a Run-seam fault test needs and returns a
// Config ready to hand to Run, plus the captured log. The opener is a real
// ConfigOpener over an empty source set: it is constructed without touching
// sops/age (decryption only happens on a resolve, which the fault paths under
// test never reach), so these seam tests run everywhere rather than skipping
// where the crypto binaries are absent.
func seamDaemon(t *testing.T, rt *runtimetest.Runtime) (Config, *syncBuffer) {
	t.Helper()
	buf := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := &config.Config{Sources: map[string]config.Source{}}
	opener := delivery.NewConfigOpener(cfg, backend.NewSOPSAge(map[string]string{}))
	return Config{
		Runtime:       rt,
		Berm:          cfg,
		Opener:        opener,
		Sink:          &fakeSink{},
		SocketPath:    filepath.Join(t.TempDir(), "berm.sock"),
		LedgerPath:    filepath.Join(t.TempDir(), "ledger.json"),
		HeartbeatPath: filepath.Join(t.TempDir(), "heartbeat"),
		Logger:        log,
	}, buf
}

// runInBackground starts the Run seam and returns a cancel and a wait helper. It
// centralizes the "drive the real entrypoint, then shut it down cleanly" shape
// the seam fault tests share, and it fails the test if Run does not return after
// cancel (a wedged daemon is itself a swallowed fault).
func runInBackground(t *testing.T, cfg Config) (cancel context.CancelFunc, wait func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()
	wait = func() {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run returned an error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Run did not return after ctx cancel (a wedged daemon)")
		}
	}
	return cancel, wait
}

// TestRun_WatchFaultSurfacesEndToEnd drives the real production entrypoint (Run)
// with a watch-subscription fault injected and asserts the daemon logs it and
// stays alive (it reconnects rather than exiting), then shuts down cleanly on
// ctx cancel. This is the watch fault surfacing through the whole wired daemon,
// not just the watchOnce method in isolation.
func TestRun_WatchFaultSurfacesEndToEnd(t *testing.T) {
	rt := newFakeRuntime()
	rt.Faults.Watch = errors.New("seam watch boom")
	cfg, buf := seamDaemon(t, rt)
	cfg.ReconcileInterval = -1 // isolate the watch path: no background reconcile

	cancel, wait := runInBackground(t, cfg)

	waitFor(t, 3*time.Second,
		func() bool { return strings.Contains(buf.String(), "runtime watch error") },
		"the watch subscription fault did not surface through the Run seam")

	cancel()
	wait()

	if !strings.Contains(buf.String(), "seam watch boom") {
		t.Errorf("the surfaced watch error did not carry its injected cause; log =\n%s", buf.String())
	}
}

// TestRun_ReconcileListFaultSurfacesEndToEnd drives Run with the reconcile pass
// enabled and List faulted, and asserts the reconcile logs the failure (so the
// next tick retries) rather than proceeding to push against an empty or partial
// listing.
func TestRun_ReconcileListFaultSurfacesEndToEnd(t *testing.T) {
	rt := newFakeRuntime()
	rt.Faults.List = errors.New("seam list boom")
	cfg, buf := seamDaemon(t, rt)
	cfg.ReconcileInterval = 5 * time.Millisecond // drive the reconcile promptly

	cancel, wait := runInBackground(t, cfg)

	waitFor(t, 3*time.Second,
		func() bool { return strings.Contains(buf.String(), "reconcile list failed") },
		"the reconcile List fault did not surface through the Run seam")

	cancel()
	wait()

	if !strings.Contains(buf.String(), "seam list boom") {
		t.Errorf("the surfaced reconcile error did not carry its injected cause; log =\n%s", buf.String())
	}
}

// TestRun_StartEventInspectFaultSurfacesEndToEnd drives Run, emits a real start
// event for a container whose Inspect is faulted, and asserts the daemon logs
// the inspect failure and does NOT push a secret to a container it could not
// identify (no injection recorded, no alert raised). This is the "no silent
// partial delivery" guarantee proven through the wired watch loop.
func TestRun_StartEventInspectFaultSurfacesEndToEnd(t *testing.T) {
	rt := newFakeRuntime()
	rt.Faults.Inspect = errors.New("seam inspect boom")
	cfg, buf := seamDaemon(t, rt)
	cfg.ReconcileInterval = -1 // isolate the start-event path
	sink := &fakeSink{}
	cfg.Sink = sink

	cancel, wait := runInBackground(t, cfg)

	rt.Emit(runtime.Event{Type: runtime.EventStart, ID: "cid-unknowable"})

	waitFor(t, 3*time.Second,
		func() bool { return strings.Contains(buf.String(), "inspect started container failed") },
		"an Inspect fault on a start event did not surface through the Run seam")

	cancel()
	wait()

	// The daemon could not identify the container, so it must not have pushed:
	// no injection recorded and no validation alert raised.
	if sink.count() != 0 {
		t.Errorf("an unidentifiable start raised %d alert(s), want 0", sink.count())
	}
	if !strings.Contains(buf.String(), "seam inspect boom") {
		t.Errorf("the surfaced inspect error did not carry its injected cause; log =\n%s", buf.String())
	}
}
