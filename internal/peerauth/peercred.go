// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package peerauth

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Ucred is the SO_PEERCRED credential of the process on the other end of a
// unix socket: the peer's process id, user id, and group id, as reported by
// the kernel to the READING process. The pid is the discriminator the
// container walk resolves; see the package doc for the pid-namespace caveat.
type Ucred struct {
	PID uint32
	UID uint32
	GID uint32
}

// peerCred reads SO_PEERCRED from an accepted unix connection. The kernel
// stamps the credential at connect time, so it identifies the process that
// actually opened the socket, not one that a later process might spoof.
func peerCred(conn *net.UnixConn) (Ucred, error) {
	if conn == nil {
		return Ucred{}, errors.New("peerauth: nil connection")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return Ucred{}, fmt.Errorf("peerauth: syscall conn: %w", err)
	}

	var cred *unix.Ucred
	var operr error
	if err := raw.Control(func(fd uintptr) {
		cred, operr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Ucred{}, fmt.Errorf("peerauth: control fd: %w", err)
	}
	if operr != nil {
		return Ucred{}, fmt.Errorf("peerauth: getsockopt SO_PEERCRED: %w", operr)
	}
	if cred == nil || cred.Pid <= 0 {
		return Ucred{}, errors.New("peerauth: SO_PEERCRED returned no usable pid")
	}
	return Ucred{
		PID: uint32(cred.Pid),
		UID: uint32(cred.Uid),
		GID: uint32(cred.Gid),
	}, nil
}
