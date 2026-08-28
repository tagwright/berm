// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package cli

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/daemon"
)

// Status prints a readable table of every berm-enabled container's injection
// state: its service, resolved delivery mechanism, delivery targets, whether the
// ledger records an injection, whether a source has drifted since, and any
// standing validation error with its class. It leads the authoritative state
// with daemon.Status (the same query a running daemon answers), and folds in the
// resolved delivery targets for the targets column. It never decrypts and never
// prints a value.
//
// Two things are surfaced prominently so they cannot scroll out of sight: the
// one-time env-exposure warning for every container that delivers env (naming
// the exposure honestly), and every sticky secrets-affecting validation error
// (an ungranted reference, a missing source, an env label without its
// acknowledgment), held until fixed.
func Status(ctx context.Context, w io.Writer, rt runtime.Runtime, cfg *config.Config, hs daemon.HashSource, ledger *daemon.Ledger) error {
	rows, err := daemon.Status(ctx, rt, cfg, hs, ledger)
	if err != nil {
		return err
	}

	// Resolved delivery targets, keyed by container id, for the targets column.
	// Both passes share resolve.Resolve, so the classification never diverges.
	targets := map[string]string{}
	if plans, perr := resolveAll(ctx, rt, cfg); perr == nil {
		for _, r := range plans {
			targets[r.ID] = planSummary(r.Plan)
		}
	}

	defDeliv := daemon.EffectiveDefaultDelivery(cfg)
	fmt.Fprintf(w, "berm status\n")
	fmt.Fprintf(w, "runtime: %s   default delivery: %s   %d enabled container(s)\n\n",
		runtimeName(cfg), defDeliv, len(rows))

	if len(rows) == 0 {
		fmt.Fprintln(w, "No berm-enabled containers found.")
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVICE\tCONTAINER\tDELIVERY\tDELIVERIES\tINJECTED\tDRIFT\tVALIDATION")
	for _, r := range rows {
		injected := "no"
		if r.Injected {
			injected = "yes"
		}
		drift := "-"
		if len(r.DriftedSources) > 0 {
			drift = fmt.Sprintf("%d", len(r.DriftedSources))
		}
		validation := "ok"
		if r.ErrorClass != "" {
			validation = "ERROR " + r.ErrorClass
			if r.Sticky {
				validation += " (sticky)"
			}
		}
		deliveries := targets[r.Container]
		if deliveries == "" {
			deliveries = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Service, shortID(r.Container), mechName(r.Mechanism), deliveries, injected, drift, validation)
	}
	tw.Flush()

	// Env-exposure warnings, one per container that delivers env, kept below the
	// table so the honest note is never lost in a wide row.
	var exposed []daemon.ContainerStatus
	for _, r := range rows {
		if r.EnvExposure {
			exposed = append(exposed, r)
		}
	}
	if len(exposed) > 0 {
		fmt.Fprintf(w, "\nenv exposure warnings:\n")
		for _, r := range exposed {
			fmt.Fprintf(w, "  %s (%s): %s. berm.env.acknowledge is affirmed.\n",
				r.Service, shortID(r.Container), envExposureNote)
		}
	}

	// Sticky secrets-affecting errors, held prominently until fixed.
	var sticky, other []daemon.ContainerStatus
	for _, r := range rows {
		if r.ErrorClass == "" {
			continue
		}
		if r.Sticky {
			sticky = append(sticky, r)
		} else {
			other = append(other, r)
		}
	}
	if len(sticky) > 0 {
		fmt.Fprintf(w, "\nvalidation errors (sticky, held until fixed):\n")
		for _, r := range sticky {
			fmt.Fprintf(w, "  %s (%s): %s: %s\n", r.Service, shortID(r.Container), r.ErrorClass, r.ErrorMessage)
		}
	}
	if len(other) > 0 {
		fmt.Fprintf(w, "\nvalidation errors:\n")
		for _, r := range other {
			fmt.Fprintf(w, "  %s (%s): %s: %s\n", r.Service, shortID(r.Container), r.ErrorClass, r.ErrorMessage)
		}
	}
	return nil
}

// runtimeName is the configured runtime name for the header, defaulting to
// docker when unset.
func runtimeName(cfg *config.Config) string {
	if cfg != nil && cfg.Globals.Runtime != "" {
		return cfg.Globals.Runtime
	}
	return "docker"
}

// shortID trims a long container id to a readable 12-char prefix, leaving a
// short id (a test's "cid-webapp") untouched.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
