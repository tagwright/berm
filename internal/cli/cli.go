// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Package cli implements berm's read-only companion subcommands: status,
// stale, validate, and suggest. cmd/berm wires thin cobra commands to these
// functions, and the functions take their dependencies as arguments so a test
// can drive them with a fake runtime, a seeded ledger, and a fixture source.
//
// Security contract (the spine, at the CLI surface). No command here decrypts
// a secret or prints a secret value. status, stale, and validate operate on
// names, paths, hashes, and structure only, never a value: they resolve labels
// against berm.yml, read ciphertext hashes, and print targets, never opening a
// source. suggest reads only the CLEARTEXT KEY NAMES from a sops-encrypted
// dotenv file (sops keeps keys in cleartext and encrypts only values as
// ENC[...]); it never runs sops -d and never prints a value. This is a hard
// invariant, covered by tests that grep command output for known plaintext and
// assert its absence.
package cli

import (
	"context"
	"sort"
	"strings"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/daemon"
	"github.com/tagwright/berm/internal/label"
	"github.com/tagwright/berm/internal/peerauth"
	"github.com/tagwright/berm/internal/resolve"
)

// resolved is one berm-enabled container resolved against berm.yml: either a
// validated Plan or a classified validation error, never both. It names
// targets, sources, and reasons only, never a secret value.
type resolved struct {
	// ID is the container id.
	ID string

	// Service is the resolved service identity, best-effort even when the
	// container failed to resolve.
	Service string

	// Plan is the validated delivery plan when the container resolved cleanly.
	Plan *resolve.Plan

	// Err is the classified validation error when the container did not resolve.
	Err *label.Error
}

// resolveAll lists the runtime's containers and resolves each berm-enabled one
// against berm.yml, exactly the way the daemon does, into a Plan or a classified
// error. Inert containers (berm.enable absent or false) are omitted. It performs
// no decryption: resolve reads only config structure and label names. Results
// are sorted by service then container for a stable report. It is the shared
// pass behind both status (for the delivery-target column) and validate.
func resolveAll(ctx context.Context, rt runtime.Runtime, cfg *config.Config) ([]resolved, error) {
	containers, err := rt.List(ctx)
	if err != nil {
		return nil, err
	}
	defDeliv := daemon.EffectiveDefaultDelivery(cfg)

	var out []resolved
	for _, c := range containers {
		svc, serr := peerauth.ServiceName(c)
		if serr != nil {
			svc = ""
		}
		plan, rerr := resolve.Resolve(resolve.Input{
			Labels:          c.Labels,
			ContainerID:     c.ID,
			Service:         svc,
			Config:          cfg,
			DefaultDelivery: defDeliv,
		})
		if plan == nil && rerr == nil {
			continue // not berm-enabled
		}
		r := resolved{ID: c.ID, Service: svc}
		if rerr != nil {
			if le, ok := label.AsError(rerr); ok {
				r.Err = le
			} else {
				r.Err = label.NewError(label.ClassBadConfig, nil, "resolve failed: see the daemon log")
			}
		} else {
			r.Plan = plan
			if r.Service == "" {
				r.Service = plan.Service
			}
		}
		out = append(out, r)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// planSummary renders a Plan's deliveries as one compact, value-free line for
// the status table: each file, env, and render target named by its shape and
// destination. It never names a value, because a Plan holds none.
func planSummary(p *resolve.Plan) string {
	if p == nil {
		return "-"
	}
	var parts []string
	for _, f := range p.Files {
		parts = append(parts, "file:"+f.Path)
	}
	for _, e := range p.Env {
		if e.All {
			parts = append(parts, "env:all("+e.Source+")")
		} else {
			parts = append(parts, "env:"+e.Var)
		}
	}
	for _, r := range p.Renders {
		parts = append(parts, string(r.Kind)+":"+r.Path)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// envExposureNote is the one honest sentence berm surfaces wherever a container
// delivers env: an env-delivered secret is readable in a way a tight-mode file
// is not. It names an exposure, never a value.
const envExposureNote = "env-delivered secrets are readable via /proc/<pid>/environ inside the " +
	"container and by host root, which a file at mode 0400 owned by the app user is not"

// mechName renders a resolved mechanism for a table cell, showing a dash for a
// container that failed to resolve to one.
func mechName(m string) string {
	if m == "" {
		return "-"
	}
	return m
}
