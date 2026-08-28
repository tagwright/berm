// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package peerauth

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Pin is a (pid, start-time) pair captured at authentication. The start-time
// is field 22 of /proc/<pid>/stat, in clock ticks since boot. The kernel never
// reuses a (pid, start-time) pair within a boot, so re-reading the start-time
// and comparing it to the pin detects a pid that has been recycled to a
// different process between authentication and a later action.
//
// Window: SO_PEERCRED reports the peer pid, and there is a small interval
// between that read and the first /proc read during Authenticate in which, if
// the peer had already exited, the pid could in principle be reused before the
// start-time is captured. That residual window is only the few syscalls inside
// one Authenticate call. For any action taken AFTER authentication the pin
// closes the reuse window entirely: Verify re-reads the start-time and rejects
// a mismatch. A caller that holds an Identity and later acts on it must call
// Verify first.
type Pin struct {
	PID       uint32
	StartTime uint64
}

// starttimeIndex is the index of field 22 (starttime) within the
// whitespace-split remainder that FOLLOWS the comm field. The remainder's
// first token is field 3 (state), so field 22 sits at index 22-3 = 19.
const starttimeIndex = 19

// parseStartTime extracts field 22 (starttime) from the contents of a
// /proc/<pid>/stat file. Field 2 (comm) is wrapped in parentheses and may
// itself contain spaces and parentheses, so the parse anchors on the LAST ")"
// and counts fields from there, which is the standard robust way to read this
// file.
func parseStartTime(content string) (uint64, error) {
	rparen := strings.LastIndexByte(content, ')')
	if rparen < 0 || rparen+1 >= len(content) {
		return 0, errors.New("peerauth: malformed stat: no comm field")
	}
	rest := strings.Fields(content[rparen+1:])
	if len(rest) <= starttimeIndex {
		return 0, fmt.Errorf("peerauth: malformed stat: only %d fields after comm", len(rest))
	}
	v, err := strconv.ParseUint(rest[starttimeIndex], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("peerauth: parse starttime %q: %w", rest[starttimeIndex], err)
	}
	return v, nil
}

// readStartTime reads /proc/<pid>/stat under the authenticator's proc root and
// returns the process start-time.
func (a *Authenticator) readStartTime(pid uint32) (uint64, error) {
	p := fmt.Sprintf("%s/%d/stat", a.procRoot, pid)
	data, err := os.ReadFile(p)
	if err != nil {
		return 0, fmt.Errorf("peerauth: read %s: %w", p, err)
	}
	return parseStartTime(string(data))
}
