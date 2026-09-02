// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Command berm-client is the one-shot client wrapper for client-mode delivery.
// It runs as the container's entrypoint, connects to the berm daemon over the
// peer-authenticated unix socket, receives only that container's own declared
// secrets, delivers them, and (in the exec form) execs the real application in
// place. It is ephemeral: the only long-lived berm process is the daemon that
// holds the key, outside the containers.
//
// Two forms:
//
//	berm-client exec -- <app> [args...]   fetch, write files, set env, exec app
//	berm-client fetch                     fetch, write files only, then exit 0
//
// The exec form is the full path and the only one that can deliver env, because
// only it controls the process environment at exec. The fetch form suits a
// files-only container using a shell entrypoint such as
// `berm-client fetch && exec <app>`, where env would not survive to the app and
// is refused with a loud warning if the bundle carries any.
//
// Socket path comes from --sock or BERM_SOCK, default /run/berm/berm.sock. The
// fetch deadline comes from BERM_CLIENT_TIMEOUT, default 30s: a fetch that does
// not complete in time fails loudly and nonzero rather than hanging forever.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/tagwright/berm/internal/client"
	"github.com/tagwright/berm/internal/version"
	"github.com/tagwright/berm/internal/wire"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run is main's testable core: it returns an exit code instead of calling
// os.Exit, and on the exec path it does not return at all on success.
func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}

	switch args[0] {
	case "version", "--version", "-v":
		fmt.Printf("berm-client %s\n", version.Version)
		return 0
	case "fetch":
		return runFetch(args[1:])
	case "exec":
		return runExec(args[1:])
	case "help", "--help", "-h":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "berm-client: unknown command %q\n", args[0])
		usage()
		return 2
	}
}

// runFetch implements the files-only form. It writes the bundle's files and
// exits. If the bundle carries env, that env cannot reach a separately-exec'd
// app, so it warns loudly: env delivery requires the exec form.
func runFetch(args []string) int {
	sock := socketFrom(args)
	ctx := context.Background()

	bundle, err := client.Fetch(ctx, sock, timeout())
	if err != nil {
		fmt.Fprintf(os.Stderr, "berm-client fetch: %v\n", err)
		return 1
	}
	defer bundle.Destroy()

	if len(bundle.Env) > 0 {
		fmt.Fprintf(os.Stderr,
			"berm-client fetch: WARNING: %d env secret(s) will NOT be delivered by the fetch form; use `berm-client exec -- <app>` for env delivery\n",
			len(bundle.Env))
	}
	if err := client.ApplyFiles(bundle, manifestPath(), requireTmpfs()); err != nil {
		fmt.Fprintf(os.Stderr, "berm-client fetch: %v\n", err)
		return 1
	}
	return 0
}

// runExec implements the full form: fetch, write files, set env, exec the app.
// The command follows a `--` separator: `berm-client exec [--sock path] -- app args`.
func runExec(args []string) int {
	sock := socketFrom(args)
	appArgs := afterDashDash(args)
	if len(appArgs) == 0 {
		fmt.Fprintln(os.Stderr, "berm-client exec: no command after --; usage: berm-client exec [--sock path] -- <app> [args...]")
		return 2
	}
	ctx := context.Background()

	bundle, err := client.Fetch(ctx, sock, timeout())
	if err != nil {
		fmt.Fprintf(os.Stderr, "berm-client exec: %v\n", err)
		return 1
	}
	// Exec replaces this process on success; on failure it returns and we Destroy.
	if err := client.Exec(bundle, appArgs, manifestPath(), requireTmpfs()); err != nil {
		bundle.Destroy()
		fmt.Fprintf(os.Stderr, "berm-client exec: %v\n", err)
		return 1
	}
	return 0 // unreachable on success
}

// socketFrom returns the daemon socket path: a --sock flag wins, else BERM_SOCK,
// else the default.
func socketFrom(args []string) string {
	if v := flagValue(args, "--sock"); v != "" {
		return v
	}
	if v := os.Getenv("BERM_SOCK"); v != "" {
		return v
	}
	return client.DefaultSocket
}

// timeout returns the fetch deadline from BERM_CLIENT_TIMEOUT, default 30s.
func timeout() time.Duration {
	if v := os.Getenv("BERM_CLIENT_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return client.DefaultTimeout
}

// manifestPath is where the client writes the delivered manifest, default the
// shared tmpfs path, overridable with BERM_MANIFEST_PATH.
func manifestPath() string {
	if v := os.Getenv("BERM_MANIFEST_PATH"); v != "" {
		return v
	}
	return wire.DefaultManifestPath
}

// requireTmpfs reports whether the client enforces the tmpfs-only destination
// rule. It is always on in production. A test container without a tmpfs mount
// can set BERM_CLIENT_ALLOW_NONTMPFS=1 to relax it, accepting that one lost
// guarantee for that run.
func requireTmpfs() bool {
	return os.Getenv("BERM_CLIENT_ALLOW_NONTMPFS") != "1"
}

// flagValue finds --name value or --name=value in args.
func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
		if len(a) > len(name)+1 && a[:len(name)+1] == name+"=" {
			return a[len(name)+1:]
		}
	}
	return ""
}

// afterDashDash returns the arguments following the first "--".
func afterDashDash(args []string) []string {
	for i, a := range args {
		if a == "--" {
			return args[i+1:]
		}
	}
	return nil
}

func usage() {
	fmt.Fprint(os.Stderr, `berm-client - one-shot secret fetch-and-exec wrapper

usage:
  berm-client exec [--sock path] -- <app> [args...]   fetch, deliver, exec app (env-capable)
  berm-client fetch [--sock path]                      fetch and deliver files only, then exit
  berm-client version

env:
  BERM_SOCK              daemon socket path (default /run/berm/berm.sock)
  BERM_CLIENT_TIMEOUT    fetch deadline (default 30s)
`)
}
