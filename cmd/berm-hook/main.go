// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Command berm-hook is the Podman OCI pre-start hook for hook-mode delivery. The
// runtime invokes it in the pre-start stage with the OCI container state JSON on
// stdin. It reads the container id from that state, fetches the container's file
// bundle from the berm daemon over the hook-request protocol, and writes those
// files into the container's own mount namespace before PID 1 runs. Files only:
// env is refused end to end in hook mode.
//
// It is a trusted, privileged host-side component the operator installs via
// Podman's hooks_dir. Unlike the one-shot client it presents a container id and
// is not peer-authenticated; the daemon validates that the id has berm labels
// before it resolves anything.
//
// The binary is deliberately lean: it links only the leaf wire package and the
// hook helpers, not the daemon's runtime and crypto stack, because a hook runs
// per container start and must be fast.
//
// Environment:
//
//	BERM_SOCK                  daemon socket (default /run/berm/berm.sock)
//	BERM_HOOK_TIMEOUT          fetch deadline (default 30s)
//	BERM_MANIFEST_PATH         manifest path inside the container (default /run/berm/manifest)
//	BERM_HOOK_ALLOW_NONTMPFS=1 relax the tmpfs-only rule (testing only)
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/tagwright/berm/internal/hook"
	"github.com/tagwright/berm/internal/version"
	"github.com/tagwright/berm/internal/wire"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run is main's testable core: it returns an exit code instead of calling
// os.Exit.
func run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-v":
			fmt.Printf("berm-hook %s\n", version.Version)
			return 0
		case "help", "--help", "-h":
			usage()
			return 0
		default:
			fmt.Fprintf(os.Stderr, "berm-hook: unexpected argument %q; the hook reads OCI state on stdin\n", args[0])
			usage()
			return 2
		}
	}

	state, err := hook.ParseState(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "berm-hook: %v\n", err)
		return 1
	}

	ctx := context.Background()
	bundle, err := hook.Fetch(ctx, socket(), state.ID, state.Annotations, timeout())
	if err != nil {
		fmt.Fprintf(os.Stderr, "berm-hook: fetch for %s: %v\n", state.ID, err)
		return 1
	}
	defer bundle.Destroy()

	if err := inject(bundle, state, manifestPath(), requireTmpfs()); err != nil {
		fmt.Fprintf(os.Stderr, "berm-hook: inject into %s: %v\n", state.ID, err)
		return 1
	}
	return 0
}

// inject writes the bundle into the container's own mount namespace before PID 1,
// selecting the path by the OCI hook stage shape the state describes:
//
//   - A host-side stage (prestart, or createRuntime on a runtime whose mounts are
//     ready by then) hands a valid container pid in the runtime's namespace. Enter
//     that mount namespace by pid via WriteIntoMountNS.
//   - The createContainer stage berm ships (see deploy/hook/hooks.d) runs the hook
//     INSIDE the container's mount namespace already, so the state carries a zero
//     pid. The mounts (the tmpfs) exist but pivot_root has not run, so the tmpfs
//     paths live under the container rootfs: write there with WriteFilesUnderRoot,
//     no setns. This is the path proven live against crun/Podman; createRuntime
//     fired before the container tmpfs existed and could not land the secret.
func inject(bundle *wire.Bundle, state hook.State, manifestPath string, requireTmpfs bool) error {
	if state.PID > 0 {
		return hook.WriteIntoMountNS(bundle, state.PID, manifestPath, requireTmpfs)
	}
	root, err := hook.ContainerRoot(state)
	if err != nil {
		return err
	}
	return hook.WriteFilesUnderRoot(bundle, root, manifestPath, requireTmpfs)
}

func socket() string {
	if v := os.Getenv("BERM_SOCK"); v != "" {
		return v
	}
	return hook.DefaultSocket
}

func timeout() time.Duration {
	if v := os.Getenv("BERM_HOOK_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return hook.DefaultTimeout
}

func manifestPath() string {
	if v := os.Getenv("BERM_MANIFEST_PATH"); v != "" {
		return v
	}
	return wire.DefaultManifestPath
}

// requireTmpfs reports whether the hook enforces the tmpfs-only destination
// rule. Always on in production; a test container without a tmpfs mount can set
// BERM_HOOK_ALLOW_NONTMPFS=1 to relax it, accepting that one lost guarantee.
func requireTmpfs() bool {
	return os.Getenv("BERM_HOOK_ALLOW_NONTMPFS") != "1"
}

func usage() {
	fmt.Fprint(os.Stderr, `berm-hook - Podman OCI pre-start hook for hook-mode secret delivery

The runtime invokes this hook with the OCI container state JSON on stdin. It
reads the container id, fetches that container's file bundle from the berm
daemon, and writes the files into the container's mount namespace before PID 1.

env:
  BERM_SOCK             daemon socket path (default /run/berm/berm.sock)
  BERM_HOOK_TIMEOUT     fetch deadline (default 30s)
  BERM_MANIFEST_PATH    in-container manifest path (default /run/berm/manifest)
`)
}
