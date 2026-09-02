// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package peerauth authenticates a caller on berm's unix socket by socket peer
// identity. It is a security boundary and is written to fail closed: any
// ambiguity, any missing /proc entry, any unresolvable container id returns an
// error and never a partial or guessed identity.
//
// The walk is SO_PEERCRED to pid to cgroup to container id to that container's
// labels, the SPIRE-proven technique that also works for rootless Podman. On
// an accepted connection the daemon reads the peer's credentials
// (SO_PEERCRED), pins the peer's process start-time to defeat pid reuse, reads
// /proc/<pid>/cgroup to extract the caller's container id, and asks the core
// runtime to Inspect that id for the container's labels. The resolved identity
// is what lets the resolver return only the caller's own declared secrets.
//
// PID-namespace caveat: SO_PEERCRED reports the peer pid as seen in the
// READING process's pid namespace. When the daemon runs in its own pid
// namespace it will see a pid it cannot resolve against the host /proc, so the
// daemon must share the host pid namespace for the walk to resolve. That
// deployment requirement is proven empirically in docs/EMPIRICAL.md (gate 2),
// not assumed here.
package peerauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/label"
)

// Identity is a fully resolved, fail-closed caller identity. Every field is
// derived from the kernel-reported peer credentials and the runtime's own view
// of the container. It carries no secret value.
type Identity struct {
	// ContainerID is the caller's full 64-hex container id, as confirmed by the
	// runtime (not merely as extracted from the cgroup).
	ContainerID string

	// ServiceName is the caller's berm service identity: the berm.name label
	// override, else the compose service label, else the container name. This
	// is what the resolver scopes secrets and grants against.
	ServiceName string

	// Labels are the caller container's labels, from the runtime. The resolver
	// reads the declared berm.* labels out of this.
	Labels map[string]string

	// Cred is the raw SO_PEERCRED credential of the peer.
	Cred Ucred

	// Pin is the (pid, start-time) pair captured at authentication, used by
	// Verify to reject a pid recycled to a different process.
	Pin Pin
}

// Authenticator resolves peers on the berm socket to container identities. It
// is safe for concurrent use: it holds only the runtime (itself concurrency
// safe) and an immutable proc root.
type Authenticator struct {
	rt       runtime.Runtime
	procRoot string
}

// New returns an Authenticator that resolves container ids against rt and reads
// process metadata from the host /proc.
func New(rt runtime.Runtime) *Authenticator {
	return &Authenticator{rt: rt, procRoot: "/proc"}
}

// Authenticate resolves the peer on conn to a container identity, failing
// closed on any error. conn must be an accepted unix-socket connection.
func (a *Authenticator) Authenticate(ctx context.Context, conn *net.UnixConn) (*Identity, error) {
	cred, err := peerCred(conn)
	if err != nil {
		return nil, err
	}
	return a.resolve(ctx, cred)
}

// resolve carries the walk from a credential to an identity. It is separated
// from the socket read so the resolution path is unit-testable against fixture
// /proc contents and a fake runtime, without a live host.
func (a *Authenticator) resolve(ctx context.Context, cred Ucred) (*Identity, error) {
	// Pin the start-time first, before the slower cgroup read and Inspect, to
	// keep the pid-reuse window as small as possible.
	st, err := a.readStartTime(cred.PID)
	if err != nil {
		return nil, fmt.Errorf("peerauth: pin start-time for pid %d: %w", cred.PID, err)
	}

	id, err := a.containerID(cred.PID)
	if err != nil {
		return nil, err
	}

	c, err := a.rt.Inspect(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("peerauth: inspect %s: %w", id, err)
	}
	// Inspect accepts a name or a prefix as well as a full id. The caller's
	// cgroup carries the full 64-hex id, so the runtime's resolved id must
	// match it exactly. A mismatch means the id resolved to a different
	// container, which we refuse rather than trust.
	if c.ID != id {
		return nil, fmt.Errorf("peerauth: inspect id mismatch: cgroup %s resolved to %s", id, c.ID)
	}

	svc, err := ServiceName(c)
	if err != nil {
		return nil, err
	}

	return &Identity{
		ContainerID: c.ID,
		ServiceName: svc,
		Labels:      c.Labels,
		Cred:        cred,
		Pin:         Pin{PID: cred.PID, StartTime: st},
	}, nil
}

// Verify re-reads the pinned process's start-time and confirms it still
// matches. A caller that holds an Identity from an earlier Authenticate and is
// about to act on it must call Verify first: a pid recycled to a different
// process since authentication has a different start-time and is rejected. A
// missing /proc entry (the peer exited) also fails closed.
func (a *Authenticator) Verify(id *Identity) error {
	if id == nil {
		return errors.New("peerauth: nil identity")
	}
	st, err := a.readStartTime(id.Pin.PID)
	if err != nil {
		return fmt.Errorf("peerauth: re-read start-time for pid %d: %w", id.Pin.PID, err)
	}
	if st != id.Pin.StartTime {
		return fmt.Errorf("peerauth: pid %d reused: start-time %d does not match pinned %d",
			id.Pin.PID, st, id.Pin.StartTime)
	}
	return nil
}

// ServiceName derives a container's berm service identity per the grammar: the
// berm.name label override, else the compose service label the runtime
// normalized, else the container name. The name suffix is honored under both
// recognized prefixes, and the same suffix under both prefixes with different
// values is a conflict the identity refuses (the ballast cross-prefix rule),
// since a security-critical identity must not be ambiguous.
//
// It is exported because the hook-mode path (which does not use SO_PEERCRED)
// needs the same berm.name-first identity derivation from an inspected
// container, and duplicating a security-critical identity computation would be a
// hazard. The peer-auth path uses it after the SO_PEERCRED walk; the hook path
// uses it on the container the daemon inspected by the presented id.
func ServiceName(c runtime.Container) (string, error) {
	name, err := bermName(c.Labels)
	if err != nil {
		return "", err
	}
	if name != "" {
		return name, nil
	}
	if c.Service != "" {
		return c.Service, nil
	}
	return strings.TrimPrefix(c.Name, "/"), nil
}

// bermName returns the berm.name override, honoring both the primary and the
// alias prefix. If both are set to different values it returns a conflict
// error rather than silently picking one.
func bermName(labels map[string]string) (string, error) {
	primary := labels[label.PrimaryPrefix+"name"]
	alias := labels[label.AliasPrefix+"name"]
	switch {
	case primary != "" && alias != "" && primary != alias:
		return "", fmt.Errorf("peerauth: conflicting berm.name: %q under primary vs %q under alias prefix", primary, alias)
	case primary != "":
		return primary, nil
	default:
		return alias, nil
	}
}
