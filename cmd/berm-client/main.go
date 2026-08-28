// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Command berm-client is the one-shot client wrapper for client-mode delivery.
// It runs as the container's entrypoint, connects to the berm daemon over the
// peer-authenticated unix socket, receives only that container's own declared
// secrets, delivers them (files, and env into the process environment at
// exec), and then execs the real application in place. It is ephemeral: the
// only long-lived berm process is the daemon that holds the key, outside the
// containers.
//
// This is a scaffold stub. A later chunk implements fetch-and-exec, the fetch
// deadline (BERM_CLIENT_TIMEOUT), and the exec handoff.
package main

import (
	"fmt"
	"os"

	"github.com/tagwright/berm/internal/version"
)

func main() {
	fmt.Fprintf(os.Stderr, "berm-client %s: not implemented\n", version.Version)
	os.Exit(1)
}
