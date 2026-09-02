// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Command gate2 is the live empirical harness for the second must-verify
// claim: that SO_PEERCRED on a berm daemon socket resolves the peer pid back
// to the CLIENT container through the socket-bind-mount topology.
//
// It has two modes. As `gate2 daemon <socket>` it listens on a unix socket in
// a shared directory, and on each accepted connection it reads the raw
// SO_PEERCRED credential and then runs the REAL peerauth.Authenticate walk
// (the same code the daemon ships) against the mounted Docker socket, printing
// both the raw credential and the resolved identity (or the fail-closed
// error). As `gate2 client <socket>` it dials that socket, holds the
// connection open so its pid stays live while the daemon resolves it, then
// exits.
//
// The harness exists only under test/. It is never part of the daemon binary.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/peerauth"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: gate2 <daemon|client> <socket-path>")
		os.Exit(2)
	}
	mode, sock := os.Args[1], os.Args[2]
	switch mode {
	case "daemon":
		runDaemon(sock)
	case "client":
		runClient(sock)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", mode)
		os.Exit(2)
	}
}

func runDaemon(sock string) {
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		fatal("listen", err)
	}
	defer ln.Close()
	fmt.Printf("GATE2 daemon listening on %s\n", sock)

	rt := runtime.NewDocker("/var/run/docker.sock")
	auth := peerauth.New(rt)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Printf("GATE2 accept error: %v\n", err)
			return
		}
		handle(auth, conn.(*net.UnixConn))
		conn.Close()
	}
}

func handle(auth *peerauth.Authenticator, conn *net.UnixConn) {
	// Raw SO_PEERCRED, printed unconditionally so the observed pid is visible
	// even when the walk fails closed.
	raw, operr := rawPeerCred(conn)
	if operr != nil {
		fmt.Printf("GATE2 rawcred error: %v\n", operr)
	} else {
		fmt.Printf("GATE2 rawcred pid=%d uid=%d gid=%d\n", raw.Pid, raw.Uid, raw.Gid)
		// Print what the daemon's /proc says for that pid, for evidence.
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", raw.Pid)); err == nil {
			fmt.Printf("GATE2 proc-cgroup pid=%d: %q\n", raw.Pid, string(b))
		} else {
			fmt.Printf("GATE2 proc-cgroup pid=%d read error: %v\n", raw.Pid, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, err := auth.Authenticate(ctx, conn)
	if err != nil {
		fmt.Printf("GATE2 RESULT: FAIL-CLOSED: %v\n", err)
		return
	}
	out, _ := json.Marshal(map[string]any{
		"container_id": id.ContainerID,
		"service":      id.ServiceName,
		"peer_pid":     id.Cred.PID,
		"labels":       id.Labels,
	})
	fmt.Printf("GATE2 RESULT: RESOLVED: %s\n", string(out))
}

func rawPeerCred(conn *net.UnixConn) (*unix.Ucred, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var operr error
	if err := rc.Control(func(fd uintptr) {
		cred, operr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return cred, operr
}

func runClient(sock string) {
	// Retry the dial briefly in case the client container starts before the
	// daemon's socket is bound.
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		conn, err = net.Dial("unix", sock)
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		fatal("dial", err)
	}
	defer conn.Close()
	fmt.Printf("GATE2 client connected to %s (my host-invisible pid=%d)\n", sock, os.Getpid())
	// Send a byte, then hold the connection open so this process stays alive
	// while the daemon resolves our SO_PEERCRED.
	_, _ = conn.Write([]byte("hello\n"))
	time.Sleep(8 * time.Second)
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "gate2 %s: %v\n", what, err)
	os.Exit(1)
}
