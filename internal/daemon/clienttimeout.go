// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"sync"
	"time"

	"github.com/tagwright/beacon"
)

// clientTracker enforces client-mode fetch safety. When a client-mode
// berm-enabled container starts, the control loop calls expect: the daemon then
// expects the container's berm-client wrapper to fetch its secrets within
// BERM_CLIENT_TIMEOUT. If the fetch arrives (the fetch handler calls arrived),
// the expectation is cleared. If the window elapses with no fetch, fire alerts
// through the sink, naming the container, so a forgotten berm-client wrapper
// surfaces loudly instead of a container silently hanging on secrets that will
// never come.
//
// It is safe for concurrent use: the control loop calls expect and cancel, the
// fetch handler calls arrived, and the timers fire on their own goroutines.
type clientTracker struct {
	mu      sync.Mutex
	timeout time.Duration
	pending map[string]*pendingClient
	sink    Sink
	baseCtx context.Context
	stopped bool
}

// pendingClient is one container awaiting its client fetch.
type pendingClient struct {
	service string
	timer   *time.Timer
}

// newClientTracker builds a tracker with the given fetch deadline, alert sink,
// and base context for the alert calls.
func newClientTracker(ctx context.Context, timeout time.Duration, sink Sink) *clientTracker {
	return &clientTracker{
		timeout: timeout,
		pending: map[string]*pendingClient{},
		sink:    sink,
		baseCtx: ctx,
	}
}

// expect registers a client-mode container to fetch within the timeout. A
// duplicate expect for a container already pending is ignored, so a repeated
// start event does not stack timers. A zero or negative timeout disables the
// check entirely (the expectation is simply not tracked).
func (t *clientTracker) expect(containerID, service string) {
	if t.timeout <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return
	}
	if _, ok := t.pending[containerID]; ok {
		return
	}
	id := containerID
	timer := time.AfterFunc(t.timeout, func() { t.fire(id) })
	t.pending[containerID] = &pendingClient{service: service, timer: timer}
}

// arrived clears the expectation for a container whose fetch handler ran. It is
// called from the fetch dispatch path. A container not being tracked (a fetch
// from a hook/volume container, or a fetch after the timeout already fired) is a
// harmless no-op.
func (t *clientTracker) arrived(containerID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.pending[containerID]; ok {
		p.timer.Stop()
		delete(t.pending, containerID)
	}
}

// cancel drops the expectation for a container that stopped or was destroyed
// before it ever fetched, so a container that never started its app does not
// trip a spurious timeout alert. It is the same clearing as arrived, kept as a
// distinct name so the call sites read for what they mean.
func (t *clientTracker) cancel(containerID string) {
	t.arrived(containerID)
}

// fire is the timer callback. If the container is still pending (no fetch, no
// cancel), it alerts and drops the expectation. A container cleared between the
// timer firing and this taking the lock is a no-op.
func (t *clientTracker) fire(containerID string) {
	t.mu.Lock()
	p, ok := t.pending[containerID]
	if !ok {
		t.mu.Unlock()
		return
	}
	delete(t.pending, containerID)
	service := p.service
	sink := t.sink
	ctx := t.baseCtx
	t.mu.Unlock()

	if sink == nil {
		return
	}
	_ = sink.Alert(ctx, beacon.LevelWarning,
		"berm client fetch timeout",
		"a client-mode container started but no berm-client fetch arrived within the timeout: check that its entrypoint runs the berm-client wrapper",
		map[string]string{
			"container": containerID,
			"service":   service,
			"timeout":   t.timeout.String(),
		})
}

// stop halts every pending timer and marks the tracker closed, for daemon
// shutdown. No further expectations are accepted after stop.
func (t *clientTracker) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
	for id, p := range t.pending {
		p.timer.Stop()
		delete(t.pending, id)
	}
}
