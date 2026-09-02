// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package cli

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/daemon"
	"github.com/tagwright/berm/internal/resolve"
)

// Validate dry-runs the manifest with NO injection and NO decryption. It
// enumerates every berm-enabled container the runtime reports, resolves each
// against berm.yml the way the daemon would, and prints what WOULD be delivered
// (each delivery's source, key or whole payload, target path or env var,
// mechanism, owner, and mode) plus every classified validation error, marking
// the sticky ones. It is the pre-deploy safety check: it returns a non-nil error
// when any container has a validation error, so a CI job fails on a broken
// manifest. It never decrypts and never prints a value.
func Validate(ctx context.Context, w io.Writer, rt runtime.Runtime, cfg *config.Config) error {
	rows, err := resolveAll(ctx, rt, cfg)
	if err != nil {
		return err
	}

	defDeliv := daemon.EffectiveDefaultDelivery(cfg)
	fmt.Fprintln(w, "berm validate")
	fmt.Fprintf(w, "runtime: %s   default delivery: %s   %d enabled container(s)\n",
		runtimeName(cfg), defDeliv, len(rows))

	if len(rows) == 0 {
		fmt.Fprintln(w, "\nNo berm-enabled containers found. Nothing to validate.")
		return nil
	}

	ok, bad := 0, 0
	for _, r := range rows {
		fmt.Fprintln(w)
		if r.Err != nil {
			bad++
			sticky := ""
			if r.Err.Sticky() {
				sticky = " (sticky)"
			}
			fmt.Fprintf(w, "%s (%s): ERROR %s%s\n", serviceOrDash(r.Service), shortID(r.ID), r.Err.Class, sticky)
			fmt.Fprintf(w, "  %s\n", r.Err.Message)
			continue
		}
		ok++
		printPlan(w, r)
	}

	fmt.Fprintf(w, "\nSummary: %d ok, %d with errors.\n", ok, bad)
	if bad > 0 {
		// A non-nil error makes cmd/berm exit nonzero, which is what makes
		// validate usable as a CI gate. cobra is configured to silence the
		// error text, so the printed report above is the whole output.
		return fmt.Errorf("validate: %d container(s) failed validation", bad)
	}
	return nil
}

// printPlan prints one clean container's resolved deliveries, target by target.
// It names sources, keys, paths, vars, owners, and modes only, never a value.
func printPlan(w io.Writer, r resolved) {
	p := r.Plan
	fmt.Fprintf(w, "%s (%s): OK\n", serviceOrDash(r.Service), shortID(r.ID))
	fmt.Fprintf(w, "  %s delivery\n", p.Mechanism)

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for _, f := range p.Files {
		what := "key " + f.Key
		if f.Whole {
			what = "whole payload"
		}
		pointer := "-"
		if f.PointerVar != "" {
			pointer = f.PointerVar
		}
		fmt.Fprintf(tw, "  file\t%s\tsource %s\t%s\t-> %s\towner %s\tmode %s\tpointer %s\n",
			f.Name, f.Source, what, f.Path, f.Owner, f.Mode, pointer)
	}
	for _, e := range p.Env {
		if e.All {
			fmt.Fprintf(tw, "  env\tall\tsource %s\tevery key\t-> process environment\t\t\t\n", e.Source)
			continue
		}
		fmt.Fprintf(tw, "  env\t%s\tsource %s\tkey %s\t-> process environment\t\t\t\n", e.Var, e.Source, e.Key)
	}
	for _, rn := range p.Renders {
		fmt.Fprintf(tw, "  %s\t%s\tsource %s\twhole source\t-> %s\towner %s\tmode %s\t\n",
			renderLabel(rn.Kind), "", rn.Source, rn.Path, rn.Owner, rn.Mode)
	}
	tw.Flush()

	if p.EnvExposure {
		fmt.Fprintf(w, "  note: %s.\n", envExposureNote)
	}
}

// renderLabel names a render kind for the plan print.
func renderLabel(k resolve.RenderKind) string {
	return string(k)
}
