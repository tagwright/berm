// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tagwright/berm/internal/daemon"
)

// Healthz is the liveness probe behind `berm healthz`, meant to be run as a
// container healthcheck from inside the daemon's own container (the distroless
// image has no shell, so the check must be the berm binary itself). It reads the
// heartbeat the daemon writes once per reconcile pass and reports healthy only
// when that beat is fresh, which distinguishes a reconcile loop that is still
// ticking from one that has hung while its process lives on. A missing beat
// (daemon down, or its reconcile loop never started) and a stale beat both
// report unhealthy and return a non-error nil only when fresh; the returned
// error is what drives the command's non-zero exit.
//
// It reads a timestamp file and nothing else: it opens no socket, loads no
// config, and decrypts nothing, so it can never surface a secret value. Its
// output names only the heartbeat path and durations.
func Healthz(w io.Writer, path string, staleAfter time.Duration, now time.Time) error {
	fresh, age, err := daemon.HeartbeatFresh(path, now, staleAfter)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(w, "berm: unhealthy: no heartbeat at %s; the daemon reconcile loop is not running\n", path)
			return fmt.Errorf("berm healthz: no heartbeat at %s", path)
		}
		fmt.Fprintf(w, "berm: unhealthy: heartbeat at %s is unreadable: %v\n", path, err)
		return fmt.Errorf("berm healthz: unreadable heartbeat")
	}
	if !fresh {
		fmt.Fprintf(w, "berm: unhealthy: heartbeat at %s is %s old (threshold %s); the reconcile loop is not progressing\n",
			path, age.Round(time.Millisecond), staleAfter)
		return fmt.Errorf("berm healthz: stale heartbeat")
	}
	fmt.Fprintf(w, "berm: healthy: reconcile loop last beat %s ago (threshold %s)\n",
		age.Round(time.Millisecond), staleAfter)
	return nil
}
