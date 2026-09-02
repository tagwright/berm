// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tagwright/beacon"

	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/label"
)

func TestComposeDigestDriftAndSticky(t *testing.T) {
	now := time.Unix(1735689600, 0).UTC()
	drift := []Drift{
		{Container: "cid-webapp", Service: "webapp", Source: "webapp"},
		{Container: "cid-db", Service: "db", Source: "shared-db", Missing: true},
	}
	sticky := []stickyError{
		{Container: "cid-x", Service: "x", Class: "ungranted_ref", Message: "service \"x\" may not read source \"y\""},
	}

	n := composeDigest(drift, sticky, now)

	// Sticky present raises the level to error.
	if n.Level != beacon.LevelError {
		t.Errorf("level = %v, want error", n.Level)
	}
	if n.Fields["drift"] != "2" || n.Fields["sticky"] != "1" {
		t.Errorf("fields = %+v, want drift=2 sticky=1", n.Fields)
	}
	// The body names every container, service, and source.
	for _, want := range []string{"webapp", "shared-db", "source now missing", "ungranted_ref", "cid-x"} {
		if !strings.Contains(n.Body, want) {
			t.Errorf("digest body missing %q:\n%s", want, n.Body)
		}
	}
}

func TestComposeDigestAllClear(t *testing.T) {
	n := composeDigest(nil, nil, time.Unix(1735689600, 0).UTC())
	if n.Level != beacon.LevelInfo {
		t.Errorf("all-clear level = %v, want info", n.Level)
	}
	if !strings.Contains(n.Body, "no drift") {
		t.Errorf("all-clear body missing the clear line:\n%s", n.Body)
	}
}

// TestSendDigestThroughSink drives the full compose-and-send path: a recorded
// injection whose source then rotates, plus a standing sticky error, composed
// and sent through the fake sink as one notification.
func TestSendDigestThroughSink(t *testing.T) {
	const secretVal = "digest-secret-value-778899"
	opener, cfg := realOpener(t,
		sopsSource{
			name:   "webapp",
			format: backend.FormatDotenv,
			dotenv: []kv{{"DB_PASSWORD", secretVal}},
		},
	)

	sink := &fakeSink{}
	d, err := New(Config{
		Runtime:    newFakeRuntime(),
		Berm:       cfg,
		Opener:     opener,
		Sink:       sink,
		LedgerPath: filepath.Join(t.TempDir(), "ledger.json"),
		Clock:      func() time.Time { return time.Unix(1735689600, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Record an injection, then rotate the source so it drifts.
	recordOnePlan(t, d.ledger, opener, "cid-webapp", "webapp", "webapp", "DB_PASSWORD")
	f, _ := os.OpenFile(cfg.Sources["webapp"].File, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("\n# rotated\n")
	f.Close()

	// Add a standing sticky validation error the way the resolve path would.
	d.sticky.add("cid-other", "other", label.NewError(label.ClassEnvNoAck, map[string]string{"container": "cid-other"}, "env label without acknowledgment"))

	if err := d.SendDigest(context.Background()); err != nil {
		t.Fatalf("send digest: %v", err)
	}

	if sink.count() != 1 {
		t.Fatalf("want 1 digest notification, got %d", sink.count())
	}
	got := sink.all()[0]
	if got.Fields["drift"] != "1" || got.Fields["sticky"] != "1" {
		t.Errorf("digest fields = %+v, want drift=1 sticky=1", got.Fields)
	}
	if !strings.Contains(got.Body, "webapp") || !strings.Contains(got.Body, "env_no_acknowledge") {
		t.Errorf("digest body missing drift/sticky detail:\n%s", got.Body)
	}
	// The digest carries no secret value.
	assertNoValue(t, "digest", sink.text(), secretVal)
}
