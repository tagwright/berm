// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tagwright/beacon"
)

// runDigest runs the scheduled staleness digest. On each tick it composes the
// current drift (sources that changed since their last injection) and the
// standing sticky validation errors into one beacon notification and sends it
// through the sink. The cadence is BERM_DIGEST_SCHEDULE (daily default). The
// digest is how a rotated-but-not-recreated secret and a still-broken container
// surface on a schedule instead of scrolling out of a live log.
func (d *Daemon) runDigest(ctx context.Context) {
	interval := parseSchedule(d.digestSchedule())
	if interval <= 0 {
		d.log.Warn("digest schedule invalid, disabling digest", "schedule", d.digestSchedule())
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	d.log.Info("berm stale digest scheduled", "interval", interval.String())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := d.SendDigest(ctx); err != nil {
				d.log.Error("send stale digest failed", "err", err.Error())
			}
		}
	}
}

// digestSchedule returns the effective digest cadence string.
func (d *Daemon) digestSchedule() string {
	if d.cfg.DigestSchedule != "" {
		return d.cfg.DigestSchedule
	}
	if d.berm != nil && d.berm.Globals.DigestSchedule != "" {
		return d.berm.Globals.DigestSchedule
	}
	return "daily"
}

// SendDigest composes and sends one staleness digest immediately. It is exported
// so cmd/berm and a test can drive one digest without waiting for the schedule.
// It reports names, sources, hashes, and reasons only, never a secret value.
func (d *Daemon) SendDigest(ctx context.Context) error {
	drift, err := d.ledger.Drift(hashSourceOf(d.opener))
	if err != nil {
		return err
	}
	sticky := d.sticky.list()
	n := composeDigest(drift, sticky, d.now())
	if d.sink == nil {
		return nil
	}
	return d.sink.Alert(ctx, n.Level, n.Title, n.Body, n.Fields)
}

// composeDigest builds the digest notification from the current drift and sticky
// errors. An all-clear digest is info; any drift or sticky error raises it to a
// warning (drift is a rotate-me nudge) or error (a sticky secrets-affecting
// failure is more urgent). The body names containers and sources only. The
// fields carry machine-readable counts.
func composeDigest(drift []Drift, sticky []stickyError, now time.Time) beacon.Notification {
	level := beacon.LevelInfo
	if len(drift) > 0 {
		level = beacon.LevelWarning
	}
	if len(sticky) > 0 {
		level = beacon.LevelError
	}

	var b strings.Builder
	fmt.Fprintf(&b, "berm staleness digest %s\n", now.UTC().Format(time.RFC3339))

	if len(drift) == 0 && len(sticky) == 0 {
		b.WriteString("no drift, no sticky validation errors: every injected secret is current.\n")
	}

	if len(drift) > 0 {
		fmt.Fprintf(&b, "\nDrift (%d): sources changed since last injection, recreate to pick up:\n", len(drift))
		sorted := append([]Drift(nil), drift...)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].Service != sorted[j].Service {
				return sorted[i].Service < sorted[j].Service
			}
			return sorted[i].Source < sorted[j].Source
		})
		for _, dr := range sorted {
			state := "changed"
			if dr.Missing {
				state = "source now missing"
			}
			fmt.Fprintf(&b, "  - %s (%s) source %q: %s\n", shortID(dr.Container), dr.Service, dr.Source, state)
		}
	}

	if len(sticky) > 0 {
		fmt.Fprintf(&b, "\nSticky validation errors (%d): secrets-affecting, fix and recreate:\n", len(sticky))
		sorted := append([]stickyError(nil), sticky...)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].Service != sorted[j].Service {
				return sorted[i].Service < sorted[j].Service
			}
			return sorted[i].Container < sorted[j].Container
		})
		for _, se := range sorted {
			fmt.Fprintf(&b, "  - %s (%s) [%s]: %s\n", shortID(se.Container), se.Service, se.Class, se.Message)
		}
	}

	return beacon.Notification{
		Title: "berm staleness digest",
		Body:  b.String(),
		Level: level,
		Fields: map[string]string{
			"drift":  fmt.Sprintf("%d", len(drift)),
			"sticky": fmt.Sprintf("%d", len(sticky)),
		},
	}
}

// parseSchedule maps a cadence keyword or a Go duration to an interval. The
// named cadences match the grammar's vocabulary; a bare duration ("30s", "1h")
// is accepted too so a test or an operator can set a tight cadence. An
// unrecognized value returns zero, which disables the digest loudly.
func parseSchedule(s string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "daily":
		return 24 * time.Hour
	case "hourly":
		return time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return 0
}

// shortID trims a full container id to its 12-char short form for a readable
// digest line, leaving a shorter id untouched.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// hashSourceOf adapts a delivery.Opener to the ledger's HashSource seam. The
// Opener already exposes SourceCipherHash, so this is an identity adapter that
// keeps the ledger free of a delivery import.
func hashSourceOf(o interface {
	SourceCipherHash(string) (string, error)
}) HashSource {
	return o
}
