// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Package client is the apply half of the one-shot berm-client: connect to the
// daemon, receive this container's bundle, land its files on tmpfs, and, in the
// exec form, set its env vars into the process environment immediately before
// exec. It imports only the leaf wire package, so the berm-client binary stays
// small and free of the daemon's runtime and crypto stack.
//
// The apply step is factored apart from the final exec so it is testable: a test
// serves a known bundle over an in-process socket, runs Fetch and ApplyFiles and
// EnvFor, and asserts the files landed and the environment is correct, without
// the process actually being replaced.
//
// Security contract: the client never writes the bundle to disk except as the
// tmpfs files it is meant to become, and never writes plaintext to a persistent
// path (WriteTmpfsFile refuses a non-tmpfs destination unless a test relaxes
// it). Secret env values necessarily become "NAME=value" strings at the exec
// boundary, because the exec syscall takes a string environment; that is the one
// place an env-delivered secret is a string, and it is in this process's own
// environ, never in docker inspect.
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tagwright/berm/internal/wire"
)

// DefaultSocket is the daemon socket the client dials when neither the flag nor
// BERM_SOCK overrides it. It is under the same tmpfs run dir as the secrets.
const DefaultSocket = "/run/berm/berm.sock"

// DefaultTimeout is the BERM_CLIENT_TIMEOUT fallback: if the whole fetch does
// not complete within this window the client gives up loudly rather than hang
// waiting for secrets that may never come.
const DefaultTimeout = 30 * time.Second

// Fetch dials the daemon at sockPath, requests the caller's bundle, and returns
// it. The whole exchange is bounded by timeout: a daemon that never answers
// surfaces as a deadline error, not a hang. The returned bundle holds secret
// bytes in locked memory; the caller MUST Destroy it.
func Fetch(ctx context.Context, sockPath string, timeout time.Duration) (*wire.Bundle, error) {
	deadline := time.Now().Add(timeout)
	d := net.Dialer{Deadline: deadline}
	conn, err := d.DialContext(ctx, "unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("client: connect to daemon at %s: %w", sockPath, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("client: set deadline: %w", err)
	}

	if err := wire.WriteRequest(conn); err != nil {
		return nil, err
	}
	bundle, err := wire.ReadResponse(conn)
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

// ApplyFiles writes every secret file in the bundle to its tmpfs path with the
// bundle's numeric owner and octal mode, and writes the manifest last (at
// manifestPath, so its atomic appearance signals that every file is in place).
// It is used by both the fetch form (files only) and the exec form.
// requireTmpfs is true in production; a test may clear it where the CI container
// lacks a tmpfs mount.
func ApplyFiles(b *wire.Bundle, manifestPath string, requireTmpfs bool) error {
	for _, f := range b.Files {
		if err := wire.WriteBytesFile(f.Path, f.Owner, f.Mode, requireTmpfs, f.Data); err != nil {
			return fmt.Errorf("client: apply file %q: %w", f.Path, err)
		}
	}
	if len(b.Manifest) > 0 {
		if err := wire.WriteBytesFile(manifestPath, "0:0", "0444", requireTmpfs, b.Manifest); err != nil {
			return fmt.Errorf("client: write manifest: %w", err)
		}
	}
	return nil
}

// EnvFor builds the environment for the exec form: the base environment (the
// client's own, less any collision), plus the bundle's non-secret _FILE
// pointers, plus its secret env vars. A pointer or secret var replaces any
// same-named entry in base rather than duplicating it. This is the one point an
// env-delivered secret becomes a string, at the exec boundary and in this
// process only.
func EnvFor(base []string, b *wire.Bundle) []string {
	set := map[string]string{}
	order := []string{}
	add := func(name, val string) {
		if _, seen := set[name]; !seen {
			order = append(order, name)
		}
		set[name] = val
	}
	for _, kv := range base {
		if i := indexByte(kv, '='); i >= 0 {
			add(kv[:i], kv[i+1:])
		}
	}
	for _, p := range b.Pointers {
		add(p.Name, p.Path)
	}
	for _, e := range b.Env {
		add(e.Name, string(e.Value))
	}
	out := make([]string, 0, len(order))
	for _, name := range order {
		out = append(out, name+"="+set[name])
	}
	return out
}

// indexByte is a tiny local to avoid pulling strings/bytes for one call.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// Exec applies the bundle (files, then env) and replaces the current process
// with argv via execve, so the app inherits the assembled environment and
// becomes the container's main process. It returns only on failure: on success
// the process image is replaced and control never comes back. The bundle is
// Destroyed just before the exec, the last moment its locked secret bytes are
// needed (their values are already folded into the exec environment strings).
func Exec(b *wire.Bundle, argv []string, manifestPath string, requireTmpfs bool) error {
	if len(argv) == 0 {
		return errors.New("client: exec needs a command")
	}
	if err := ApplyFiles(b, manifestPath, requireTmpfs); err != nil {
		return err
	}
	env := EnvFor(os.Environ(), b)
	path, err := lookPath(argv[0])
	if err != nil {
		return fmt.Errorf("client: locate %q: %w", argv[0], err)
	}
	// The env slice now carries the secret values; the locked buffers are no
	// longer needed, so wipe them before handing off.
	b.Destroy()
	if err := unix.Exec(path, argv, env); err != nil {
		return fmt.Errorf("client: exec %q: %w", path, err)
	}
	return nil // unreachable on success
}

// lookPath resolves a command to an absolute path, honoring PATH like a shell,
// so an entrypoint can name "postgres" and not "/usr/local/bin/postgres".
func lookPath(name string) (string, error) {
	if len(name) > 0 && (name[0] == '/' || name[0] == '.') {
		if _, err := os.Stat(name); err != nil {
			return "", err
		}
		return name, nil
	}
	for _, dir := range filepathSplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "."
		}
		cand := dir + "/" + name
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand, nil
		}
	}
	return "", fmt.Errorf("%q not found in PATH", name)
}

// filepathSplitList splits a PATH-style list on ':' without importing path/filepath
// for a single use in this leaf-adjacent package.
func filepathSplitList(p string) []string {
	if p == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(p); i++ {
		if p[i] == ':' {
			out = append(out, p[start:i])
			start = i + 1
		}
	}
	return append(out, p[start:])
}
