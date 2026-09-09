// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/tagwright/core/runtime"
)

// #604: the daemon's three runtime touch points (Watch, List, Inspect) all
// handle a runtime fault by logging it and moving on (the watch reconnects, the
// reconcile retries next tick, a start is skipped), never by silently
// swallowing it. That log+retry is the intended behavior, so these tests lock
// it in: each injects a fault on one runtime call and asserts the daemon
// surfaces it (the fault is logged and carries its cause) rather than dropping
// it on the floor. If a future refactor makes any of these paths eat the error
// quietly, a test here goes red.
//
// The three fault paths touch only the runtime and the logger before they
// surface and return, so these tests build a minimal Daemon directly instead of
// through New(): New's delivery path needs a real sops/age opener and would
// skip on a runner without those binaries, whereas a fault-surfacing lock-in
// must run everywhere.

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
	// The errs channel is buffered (cap 1): queue the fault, then close it so
	// watchOnce drains the error and then returns on the closed channel, the
	// same shape as a real watch stream ending.
	rt.errs <- injected
	close(rt.errs)

	d.watchOnce(context.Background())

	got := buf.String()
	if !strings.Contains(got, "runtime watch error") {
		t.Errorf("a watch-stream error was not logged (silently swallowed); log =\n%s", got)
	}
	if !strings.Contains(got, "watch stream boom") {
		t.Errorf("the logged watch error did not carry its injected cause; log =\n%s", got)
	}
}

func TestReconcileVolumes_ListErrorSurfaces(t *testing.T) {
	rt := newFakeRuntime()
	rt.listErr = errors.New("list boom")
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
	rt.inspectErr = errors.New("inspect boom")
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
