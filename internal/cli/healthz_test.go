// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tagwright/berm/internal/daemon"
)

const healthzStaleAfter = 6 * time.Second

// TestHealthzFreshIsHealthy pins the healthy path: a fresh heartbeat exits with
// no error (a zero exit for the healthcheck) and prints a healthy line.
func TestHealthzFreshIsHealthy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heartbeat")
	base := time.Unix(1735689600, 0).UTC()
	if err := daemon.WriteHeartbeat(path, base); err != nil {
		t.Fatalf("WriteHeartbeat: %v", err)
	}

	var buf bytes.Buffer
	err := Healthz(&buf, path, healthzStaleAfter, base.Add(2*time.Second))
	if err != nil {
		t.Fatalf("fresh heartbeat should be healthy (nil error), got %v", err)
	}
	if !strings.HasPrefix(buf.String(), "berm: healthy") {
		t.Errorf("output = %q, want a healthy line", buf.String())
	}
}

// TestHealthzStaleIsUnhealthy pins the stale path: a heartbeat older than the
// threshold returns an error (nonzero exit) and says so.
func TestHealthzStaleIsUnhealthy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heartbeat")
	base := time.Unix(1735689600, 0).UTC()
	if err := daemon.WriteHeartbeat(path, base); err != nil {
		t.Fatalf("WriteHeartbeat: %v", err)
	}

	var buf bytes.Buffer
	err := Healthz(&buf, path, healthzStaleAfter, base.Add(30*time.Second))
	if err == nil {
		t.Fatal("a stale heartbeat must be unhealthy (nonzero exit)")
	}
	out := buf.String()
	if !strings.HasPrefix(out, "berm: unhealthy") || !strings.Contains(out, "old") {
		t.Errorf("output = %q, want an unhealthy/stale line", out)
	}
}

// TestHealthzMissingIsUnhealthy pins that a missing heartbeat (daemon down or
// its reconcile loop never running) is unhealthy, not mistaken for healthy.
func TestHealthzMissingIsUnhealthy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-written")

	var buf bytes.Buffer
	err := Healthz(&buf, path, healthzStaleAfter, time.Now())
	if err == nil {
		t.Fatal("a missing heartbeat must be unhealthy (nonzero exit)")
	}
	out := buf.String()
	if !strings.HasPrefix(out, "berm: unhealthy") || !strings.Contains(out, "no heartbeat") {
		t.Errorf("output = %q, want an unhealthy/no-heartbeat line", out)
	}
}

// TestHealthzOutputNamesNoSecret is a belt-and-suspenders check that healthz
// output is structural only: it names the path and durations and nothing that
// could be a secret. A corrupt heartbeat body must not be echoed as content.
func TestHealthzCorruptIsUnhealthy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heartbeat")
	if err := os.WriteFile(path, []byte("garbage\n"), 0o644); err != nil {
		t.Fatalf("seed corrupt heartbeat: %v", err)
	}

	var buf bytes.Buffer
	err := Healthz(&buf, path, healthzStaleAfter, time.Now())
	if err == nil {
		t.Fatal("a corrupt heartbeat must be unhealthy (nonzero exit)")
	}
	if !strings.HasPrefix(buf.String(), "berm: unhealthy") {
		t.Errorf("output = %q, want an unhealthy line", buf.String())
	}
}
