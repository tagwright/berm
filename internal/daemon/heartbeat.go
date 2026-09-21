// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tagwright/berm/internal/wire"
)

// DefaultHeartbeatPath is where the daemon writes its liveness heartbeat: a tiny
// file on a writable tmpfs, updated after every reconcile pass. It is NOT a
// secret (it holds only a timestamp), so it lives on its own tmpfs mount kept
// well away from the secret paths, and `berm healthz` reads it to tell a
// reconcile loop that is still ticking from one that has hung.
//
// The path is deliberately its own top-level mount (/run/berm-health), not
// nested under /run/berm, so it never collides with the socket, the age-key
// mount, or a volume-mode shared volume in any of the three deploy topologies.
// The gated deploy adds the matching `tmpfs: - /run/berm-health` to the daemon
// service (see docs/OPERATIONS.md).
const DefaultHeartbeatPath = "/run/berm-health/heartbeat"

// DefaultHeartbeatStaleAfter is how old the heartbeat may be before `berm
// healthz` reports the daemon unhealthy. It is three reconcile intervals, so a
// single slow or skipped pass never trips a false alarm but a genuinely hung
// reconcile loop is caught within a few seconds. It tracks DefaultReconcileInterval.
const DefaultHeartbeatStaleAfter = 3 * DefaultReconcileInterval

// WriteHeartbeat atomically writes t as the daemon's liveness heartbeat at path.
// It reuses the shared tmpfs writer (temp-then-rename within the destination
// directory) so a reader never observes a partial file, and it chowns the file
// to the calling process's own uid, which never needs privilege. The heartbeat
// is not a secret, so the tmpfs guarantee is not enforced here (its value is a
// timestamp, never plaintext); keeping it on tmpfs is a deploy-mount concern,
// documented for the operator, not a write-time refusal that would couple
// liveness reporting to a mount check.
func WriteHeartbeat(path string, t time.Time) error {
	owner := strconv.Itoa(os.Getuid())
	return wire.WriteBytesFile(path, owner, "0644", false, []byte(strconv.FormatInt(t.UnixNano(), 10)+"\n"))
}

// ReadHeartbeat reads and parses the timestamp the daemon last wrote to path. A
// missing file returns an error that os.IsNotExist reports true for, so the
// caller can distinguish "daemon never started or its reconcile loop is not
// running" from a merely stale beat.
func ReadHeartbeat(path string) (time.Time, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	ns, perr := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if perr != nil {
		return time.Time{}, fmt.Errorf("heartbeat: %q is not a valid timestamp: %w", path, perr)
	}
	return time.Unix(0, ns).UTC(), nil
}

// HeartbeatFresh reports whether the heartbeat at path was written within
// staleAfter of now, along with its age. A fresh heartbeat proves the daemon's
// reconcile loop completed a pass recently, which is the liveness signal a bare
// process check cannot give: a hung-but-running daemon stops beating while its
// PID lives on. A clock that has moved backward since the write yields a
// non-negative (clamped to zero) age rather than a spurious staleness.
func HeartbeatFresh(path string, now time.Time, staleAfter time.Duration) (fresh bool, age time.Duration, err error) {
	hb, err := ReadHeartbeat(path)
	if err != nil {
		return false, 0, err
	}
	age = now.Sub(hb)
	if age < 0 {
		age = 0
	}
	return age <= staleAfter, age, nil
}

// beat records one liveness heartbeat with the daemon's clock. It is called once
// per reconcile pass, so the timestamp only advances while the reconcile
// goroutine is actually running; a hung pass stops updating it and healthz goes
// stale. A write failure is logged and swallowed: it must never take the daemon
// down, and a heartbeat that stops appearing is itself the signal healthz reads.
func (d *Daemon) beat() {
	if d.heartbeatPath == "" {
		return
	}
	if err := WriteHeartbeat(d.heartbeatPath, d.now()); err != nil {
		d.log.Warn("heartbeat write failed", "path", d.heartbeatPath, "err", err.Error())
	}
}
