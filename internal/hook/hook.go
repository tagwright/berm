// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Package hook is the host-side half of the Podman OCI pre-start hook: parse the
// OCI runtime state the runtime hands the hook on stdin, fetch the container's
// file bundle from the berm daemon, and write those files into the container's
// own mount namespace before PID 1 runs. It imports only the leaf wire package,
// so the berm-hook binary stays small and free of the daemon's runtime and
// crypto stack, the way the client binary does.
//
// Trust model, distinct from the client. The hook is a trusted, privileged
// host-side component the operator installs via Podman's hooks_dir. It runs as
// root and has no peer container identity of its own, so it presents the OCI
// container id AND the container's OCI annotations (its berm.* config) from the
// state JSON to the daemon. The daemon resolves from those presented annotations
// rather than inspecting the container over the runtime API, because the
// pre-start hook fires while the runtime holds the container-creation lock and a
// daemon Inspect would deadlock against the create the hook is blocking. The
// daemon still validates the presented config against berm.yml before resolving.
// Contrast the client, which sends no id and is authenticated by the
// kernel-attested peer credentials of the socket.
//
// Security contract. Files only: env is refused end to end in hook mode (the
// daemon never puts env in a hook bundle). The write goes through the shared
// tmpfs writer with tmpfs enforcement on, so a secret never lands on persistent
// disk. That is why the write must happen inside the container's mount
// namespace: the secret paths must be a real tmpfs the container declared, and
// entering the mount ns is the way to write into that tmpfs rather than into the
// underlying rootfs (where a host-side rootfs write would leave plaintext on
// persistent disk, breaking the contract).
//
// Stage and write path. berm installs the hook at the OCI createContainer stage
// (see deploy/hook/hooks.d). At that stage the runtime has already run the hook
// INSIDE the container's own mount namespace and set up the container's mounts
// (the tmpfs the secret must land on), but has not yet pivot_root'd, so "/" is
// still the runtime's root and the container's tmpfs paths live UNDER the
// container rootfs. The OCI state at that stage carries a zero pid (the hook is
// already in the namespace, there is nothing to setns into) and the container
// rootfs path, so the write goes through WriteFilesUnderRoot with that rootfs as
// the prefix. This was verified empirically against crun 1.28 / Podman 5.8 in
// the nested-podman integration phase: the earlier createRuntime staging fired
// host-side BEFORE the container mounts existed, so the write could not land on
// the container tmpfs at all, which the integration pass caught and fixed.
//
// WriteIntoMountNS (the setns path) remains for a host-side stage that hands a
// valid container pid in the runtime's namespace (prestart on some runtimes):
// there the hook enters the container's mount namespace by pid. cmd/berm-hook
// selects between the two by whether the state carries a pid.
//
// What is proven now vs later. ParseState, ContainerRoot, and WriteFilesUnderRoot
// are unit tested here against a sample OCI state and a real /dev/shm tmpfs. The
// createContainer rootfs-prefixed write is proven end to end against a live
// Podman in the nested-podman integration phase (test/integration/run-podman.sh).
// WriteIntoMountNS's fail-closed behavior on a bad pid is asserted here.
package hook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tagwright/berm/internal/wire"
)

// DefaultSocket is the daemon socket the hook dials when none is configured. It
// matches the client default: the daemon exposes one socket for both request
// types.
const DefaultSocket = "/run/berm/berm.sock"

// DefaultTimeout bounds the whole fetch so a hook cannot hang a container start
// forever waiting on an unresponsive daemon.
const DefaultTimeout = 30 * time.Second

// State is the subset of the OCI runtime State (the JSON the runtime pipes to a
// hook on stdin) that the hook needs. Per the OCI runtime spec the state
// carries the container id, its status, the pid of the container process (in the
// runtime's pid namespace, which for a root hook is the host), the bundle path,
// and the container's annotations.
type State struct {
	OCIVersion string `json:"ociVersion"`
	ID         string `json:"id"`
	Status     string `json:"status"`
	PID        int    `json:"pid"`
	Bundle     string `json:"bundle"`
	// Root is the container's root filesystem path. It is a crun/runc extension
	// to the OCI state (not in the base State schema) that the createContainer
	// stage relies on: at that stage the hook runs inside the container's mount
	// namespace before pivot_root, so the container's tmpfs paths live under this
	// root. When a runtime omits it, ContainerRoot falls back to the bundle's
	// config.json.
	Root        string            `json:"root,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ParseState decodes an OCI runtime state from r (the hook's stdin) and returns
// it. A state with no container id is refused: the id is what the hook presents
// to the daemon, so an empty one cannot be acted on.
func ParseState(r io.Reader) (State, error) {
	var s State
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return State{}, fmt.Errorf("hook: parse OCI state: %w", err)
	}
	if s.ID == "" {
		return State{}, fmt.Errorf("hook: OCI state carried no container id")
	}
	return s, nil
}

// ContainerRoot resolves the container's root filesystem path from the OCI
// state, for the createContainer stage where the hook runs inside the
// container's own mount namespace but before pivot_root: there the container's
// tmpfs paths live under this root rather than at "/". It prefers the state's
// own root field (crun and runc set it), and falls back to reading root.path
// from the bundle's config.json (resolved relative to the bundle when relative)
// for a runtime that does not populate state.root. It fails closed: a state that
// carries neither a root nor a usable bundle config is an error, never a guessed
// "/".
func ContainerRoot(s State) (string, error) {
	if s.Root != "" {
		return s.Root, nil
	}
	if s.Bundle == "" {
		return "", fmt.Errorf("hook: OCI state carried neither a root nor a bundle path")
	}
	cfgPath := filepath.Join(s.Bundle, "config.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", fmt.Errorf("hook: read %s for container root: %w", cfgPath, err)
	}
	var cfg struct {
		Root struct {
			Path string `json:"path"`
		} `json:"root"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("hook: parse %s for container root: %w", cfgPath, err)
	}
	if cfg.Root.Path == "" {
		return "", fmt.Errorf("hook: %s carried no root.path", cfgPath)
	}
	if filepath.IsAbs(cfg.Root.Path) {
		return cfg.Root.Path, nil
	}
	return filepath.Join(s.Bundle, cfg.Root.Path), nil
}

// Fetch dials the daemon at sockPath and requests the file bundle for
// containerID over the hook-request protocol, presenting the container's OCI
// annotations so the daemon resolves the plan from them rather than inspecting
// the container over the runtime API (which would deadlock against the create
// the pre-start hook is blocking). The whole exchange is bounded by timeout. The
// returned bundle holds secret bytes in locked memory; the caller MUST Destroy
// it.
func Fetch(ctx context.Context, sockPath, containerID string, annotations map[string]string, timeout time.Duration) (*wire.Bundle, error) {
	deadline := time.Now().Add(timeout)
	d := net.Dialer{Deadline: deadline}
	conn, err := d.DialContext(ctx, "unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("hook: connect to daemon at %s: %w", sockPath, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("hook: set deadline: %w", err)
	}
	if err := wire.WriteHookRequest(conn, containerID, annotations); err != nil {
		return nil, err
	}
	bundle, err := wire.ReadResponse(conn)
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

// WriteFilesUnderRoot writes every file in the bundle at filepath.Join(root,
// file.Path) with the bundle's numeric owner and octal mode, then writes the
// manifest last at join(root, manifestPath). This is the byte-writing core,
// tested directly against a tmpfs temp dir. In production root is "/" (the write
// runs inside the container's mount namespace, where the tmpfs paths are the
// container's own absolute paths); a test passes a temp-dir root to land the
// files under an inspectable prefix.
//
// requireTmpfs enforces the no-plaintext-on-persistent-disk contract and is
// always set in production. Each write is temp-then-rename, so a failed write
// publishes nothing.
func WriteFilesUnderRoot(b *wire.Bundle, root, manifestPath string, requireTmpfs bool) error {
	for _, f := range b.Files {
		dst := filepath.Join(root, f.Path)
		if err := wire.WriteBytesFile(dst, f.Owner, f.Mode, requireTmpfs, f.Data); err != nil {
			return fmt.Errorf("hook: write file %q: %w", f.Path, err)
		}
	}
	if len(b.Manifest) > 0 {
		if err := wire.WriteBytesFile(filepath.Join(root, manifestPath), "0:0", "0444", requireTmpfs, b.Manifest); err != nil {
			return fmt.Errorf("hook: write manifest: %w", err)
		}
	}
	return nil
}

// WriteIntoMountNS enters the mount namespace of the container process pid and
// writes the bundle's files at their tmpfs paths there, before PID 1 runs. It is
// the production write path. The setns step requires the container to declare a
// tmpfs mount at the secret paths (so the write lands on a real tmpfs, not the
// rootfs), and requires the hook to run privileged, which is the pre-start
// admission model Podman's hooks_dir provides.
//
// The OS thread is locked and deliberately never unlocked: after setns into
// another mount namespace a thread cannot be safely returned to Go's pool, so it
// is tainted and left to die when the short-lived, one-container hook process
// exits. This is why the byte-writing is factored into WriteFilesUnderRoot,
// which is unit tested without a live namespace; the setns call itself is proven
// in the nested-podman integration phase.
func WriteIntoMountNS(b *wire.Bundle, pid int, manifestPath string, requireTmpfs bool) error {
	if pid <= 0 {
		return fmt.Errorf("hook: refusing setns for non-positive pid %d", pid)
	}

	// Open the namespace handle before touching the thread, so a bad pid fails
	// without tainting an OS thread.
	nsPath := fmt.Sprintf("/proc/%d/ns/mnt", pid)
	fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("hook: open container mount ns %s: %w", nsPath, err)
	}
	defer unix.Close(fd)

	runtime.LockOSThread()
	// No UnlockOSThread on purpose: the thread is tainted by the setns below.
	if err := unix.Setns(fd, unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("hook: setns into container mount ns (pid %d): %w", pid, err)
	}
	// Now inside the container's mount namespace: the tmpfs paths are the
	// container's own absolute paths, so write with no root prefix.
	return WriteFilesUnderRoot(b, "/", manifestPath, requireTmpfs)
}
