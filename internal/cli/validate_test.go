// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/config"
)

// validateConfig is a berm.yml with the sources the worked example uses: a
// service's own dotenv source, a granted cross-service dotenv source, and an
// auxiliary binary source. No secret value lives here.
func validateConfig() *config.Config {
	return &config.Config{
		Sources: map[string]config.Source{
			"webapp":     {File: "webapp.sops.env", Format: "dotenv"},
			"shared-db":  {File: "shared-db.sops.env", Format: "dotenv", Owner: "postgres", Access: []string{"webapp"}},
			"webapp-tls": {File: "webapp-tls.sops.bin", Format: "binary"},
		},
		Defaults: config.Defaults{Delivery: "client"},
	}
}

func TestValidatePrintsPlanAndErrorsAndExitsNonzero(t *testing.T) {
	cfg := validateConfig()
	rt := newFakeRuntime()

	// A valid container: cross-service env rename, a binary whole-payload file
	// with an owner and mode override. Resolves cleanly.
	rt.add(runtime.Container{
		ID: "cid-webapp", Name: "/webapp", Service: "webapp",
		Labels: map[string]string{
			"berm.enable":             "true",
			"berm.delivery":           "client",
			"berm.source":             "webapp",
			"berm.env.DATABASE_URL":   "shared-db/DATABASE_URL",
			"berm.env.acknowledge":    "true",
			"berm.file.tls-key.from":  "webapp-tls",
			"berm.file.tls-key.path":  "/run/berm/tls/server.key",
			"berm.file.tls-key.owner": "1000:1000",
			"berm.file.tls-key.mode":  "0440",
		},
	})
	// An invalid container: a missing source (sticky).
	rt.add(runtime.Container{
		ID: "cid-broken", Name: "/broken", Service: "broken",
		Labels: map[string]string{
			"berm.enable":      "true",
			"berm.delivery":    "client",
			"berm.file.x.from": "nope/KEY",
		},
	})
	// An inert container: omitted from the report entirely.
	rt.add(runtime.Container{ID: "cid-plain", Name: "/plain", Service: "plain"})

	var out bytes.Buffer
	err := Validate(context.Background(), &out, rt, cfg)
	if err == nil {
		t.Fatal("validate must return a non-nil error when any container fails, for CI use")
	}
	got := out.String()

	// The valid container's plan, target by target.
	for _, want := range []string{
		"webapp (cid-webapp): OK",
		"client delivery",
		"source webapp-tls",
		"whole payload",
		"/run/berm/tls/server.key",
		"owner 1000:1000",
		"mode 0440",
		"source shared-db",
		"key DATABASE_URL",
		"/proc/<pid>/environ", // env-exposure note on the plan
	} {
		if !strings.Contains(got, want) {
			t.Errorf("validate output missing %q\n---\n%s", want, got)
		}
	}

	// The invalid container's classified, sticky error.
	for _, want := range []string{
		"broken (cid-broken): ERROR missing_source (sticky)",
		"Summary: 1 ok, 1 with errors.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("validate output missing %q\n---\n%s", want, got)
		}
	}

	// The inert container never appears.
	if strings.Contains(got, "plain") {
		t.Errorf("inert container should be omitted, got:\n%s", got)
	}
}

func TestValidateCleanExitsZero(t *testing.T) {
	cfg := validateConfig()
	rt := newFakeRuntime()
	rt.add(runtime.Container{
		ID: "cid-webapp", Name: "/webapp", Service: "webapp",
		Labels: map[string]string{
			"berm.enable":           "true",
			"berm.delivery":         "client",
			"berm.file.pgpass.from": "DB_PASSWORD",
		},
	})

	var out bytes.Buffer
	if err := Validate(context.Background(), &out, rt, cfg); err != nil {
		t.Fatalf("clean validate must exit zero (nil error), got %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "Summary: 1 ok, 0 with errors.") {
		t.Errorf("clean validate summary wrong:\n%s", got)
	}
	// The auto _FILE pointer for a keyed file delivery is surfaced.
	if !strings.Contains(got, "DB_PASSWORD_FILE") {
		t.Errorf("expected the auto _FILE pointer in the plan:\n%s", got)
	}
}
