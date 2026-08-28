// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package daemon

import (
	"context"
	"testing"
	"time"
)

func TestClientTimeoutFiresWhenNoFetch(t *testing.T) {
	sink := &fakeSink{}
	tr := newClientTracker(context.Background(), 40*time.Millisecond, sink)
	defer tr.stop()

	tr.expect("cid-1", "svc-1")

	waitFor(t, time.Second, func() bool { return sink.count() > 0 }, "no fetch did not fire a timeout alert")
	got := sink.all()[0]
	if got.Fields["container"] != "cid-1" {
		t.Errorf("alert container = %q, want cid-1", got.Fields["container"])
	}
	if got.Fields["service"] != "svc-1" {
		t.Errorf("alert service = %q, want svc-1", got.Fields["service"])
	}
}

func TestClientTimeoutDoesNotFireWhenFetchArrives(t *testing.T) {
	sink := &fakeSink{}
	tr := newClientTracker(context.Background(), 60*time.Millisecond, sink)
	defer tr.stop()

	tr.expect("cid-2", "svc-2")
	// The fetch arrives well within the window.
	time.Sleep(10 * time.Millisecond)
	tr.arrived("cid-2")

	// Wait past the original deadline: no alert must fire.
	time.Sleep(120 * time.Millisecond)
	if sink.count() != 0 {
		t.Fatalf("a fetch arrived but the tracker still alerted: %+v", sink.all())
	}
}

func TestClientTimeoutCancelOnStop(t *testing.T) {
	sink := &fakeSink{}
	tr := newClientTracker(context.Background(), 60*time.Millisecond, sink)
	defer tr.stop()

	tr.expect("cid-3", "svc-3")
	time.Sleep(10 * time.Millisecond)
	tr.cancel("cid-3") // container stopped before it ever fetched

	time.Sleep(120 * time.Millisecond)
	if sink.count() != 0 {
		t.Fatalf("a cancelled expectation still alerted: %+v", sink.all())
	}
}

func TestClientTimeoutZeroDisables(t *testing.T) {
	sink := &fakeSink{}
	tr := newClientTracker(context.Background(), 0, sink)
	defer tr.stop()

	tr.expect("cid-4", "svc-4")
	time.Sleep(30 * time.Millisecond)
	if sink.count() != 0 {
		t.Fatalf("a zero timeout should disable the check, but it alerted: %+v", sink.all())
	}
}
