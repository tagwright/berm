// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package cli

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/tagwright/berm/internal/daemon"
)

// Stale reports which containers hold a source that changed since their last
// injection, so the operator knows what to recreate. It is standalone: it reads
// the persisted ledger and compares each recorded ciphertext hash to the source
// ciphertext on disk now, and it does not need the daemon running. It never
// decrypts and never prints a value: it compares ciphertext hashes only. A
// vanished source (deleted since injection) surfaces as loudly as a changed one.
// Clean output when nothing has drifted.
func Stale(w io.Writer, ledger *daemon.Ledger, hs daemon.HashSource) error {
	drift, err := ledger.Drift(hs)
	if err != nil {
		return err
	}

	fmt.Fprintln(w, "berm stale")
	if len(drift) == 0 {
		fmt.Fprintln(w, "No drift. Every injected source matches the ciphertext on disk.")
		return nil
	}

	fmt.Fprintf(w, "%d drifted source(s) since last injection. Recreate the affected container to inject the current secret.\n\n", len(drift))
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CONTAINER\tSERVICE\tSOURCE\tSTATE")
	for _, d := range drift {
		state := "changed"
		if d.Missing {
			state = "missing (source deleted since injection)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", shortID(d.Container), serviceOrDash(d.Service), d.Source, state)
	}
	tw.Flush()

	fmt.Fprintln(w, "\nRecreate each affected container (for example: docker compose up -d --no-deps <service>) to pick up the rotated secret.")
	return nil
}

// serviceOrDash shows a dash for an empty service identity in a ledger record.
func serviceOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
