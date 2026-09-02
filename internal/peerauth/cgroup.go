// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package peerauth

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	// ErrNoContainerID is returned when no container id can be extracted from a
	// process's cgroup. The authenticator treats it as a fail-closed error: a
	// caller that cannot be placed in a container authenticates as nobody.
	ErrNoContainerID = errors.New("peerauth: no container id in cgroup")

	// ErrAmbiguousContainerID is returned when a cgroup path yields more than
	// one distinct container id. Rather than guess which one is the caller, the
	// authenticator fails closed.
	ErrAmbiguousContainerID = errors.New("peerauth: ambiguous container id in cgroup")
)

// knownPrefixes are the systemd-scope and cgroupfs name prefixes that wrap a
// 64-hex container id in a cgroup path segment, across Docker and Podman (and
// the common CRI runtimes, extracted opportunistically since the shape is the
// same). The bare-segment case (Docker's cgroupfs "/docker/<id>") needs no
// prefix and is handled separately.
var knownPrefixes = []string{
	"docker-",
	"libpod-",
	"crio-",
	"cri-containerd-",
	"containerd-",
}

// isHex64 reports whether s is exactly 64 lowercase hex characters, the shape
// of a full container id.
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// idFromSegment extracts a 64-hex container id from one "/"-separated cgroup
// path segment, or "" if the segment carries none. It handles a bare id
// segment (Docker cgroupfs "/docker/<id>"), a "<prefix><id>.scope" systemd
// segment (docker-<id>.scope, libpod-<id>.scope), and the same without the
// .scope or .service suffix.
func idFromSegment(seg string) string {
	seg = strings.TrimSuffix(seg, ".scope")
	seg = strings.TrimSuffix(seg, ".service")
	if isHex64(seg) {
		return seg
	}
	for _, p := range knownPrefixes {
		if rest, ok := strings.CutPrefix(seg, p); ok && isHex64(rest) {
			return rest
		}
	}
	return ""
}

// parseCgroupContainerID extracts the caller's container id from the contents
// of a /proc/<pid>/cgroup file. It handles cgroup v2 (a single "0::<path>"
// line) and cgroup v1 (multiple "<hierarchy>:<controllers>:<path>" lines), and
// both Docker and Podman path shapes including rootless Podman nested under
// user.slice.
//
// It fails closed: no extractable id returns ErrNoContainerID, and two
// distinct ids across the lines return ErrAmbiguousContainerID. It never
// guesses and never returns a partial id.
func parseCgroupContainerID(content string) (string, error) {
	found := ""
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// Each line is hierarchy-ID:controllers:path. Only the path may itself
		// contain a colon, and the first two fields never do, so split on the
		// first two colons and keep the remainder as the path.
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		cgpath := parts[2]
		for _, seg := range strings.Split(cgpath, "/") {
			id := idFromSegment(seg)
			if id == "" {
				continue
			}
			if found != "" && found != id {
				return "", ErrAmbiguousContainerID
			}
			found = id
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("peerauth: scan cgroup: %w", err)
	}
	if found == "" {
		return "", ErrNoContainerID
	}
	return found, nil
}

// containerID reads /proc/<pid>/cgroup under the authenticator's proc root and
// extracts the caller's container id.
func (a *Authenticator) containerID(pid uint32) (string, error) {
	p := fmt.Sprintf("%s/%d/cgroup", a.procRoot, pid)
	data, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("peerauth: read %s: %w", p, err)
	}
	return parseCgroupContainerID(string(data))
}
