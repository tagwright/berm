// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/tagwright/berm/internal/delivery"
	"github.com/tagwright/berm/internal/resolve"
	"github.com/tagwright/berm/internal/wire"
)

// server is the berm unix-socket server. It accepts connections, reads one
// request frame per connection, and dispatches: a fetch request runs the
// peer-authenticated client path, a hook request runs the trusted-injector hook
// path. One goroutine per connection, all cancellable through the serve context,
// clean shutdown on close.
type server struct {
	d  *Daemon
	ln *net.UnixListener

	mu    sync.Mutex
	conns map[*net.UnixConn]struct{}
}

// listen binds the berm socket at path with tight permissions. The parent
// directory is created 0700 and the socket itself is chmod 0600, so only a
// process the operator granted socket access (the container's own uid, or root)
// can connect. A stale socket file from a previous run is removed first.
func (s *server) listen(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Remove a stale socket so bind does not fail with "address in use".
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return err
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	s.ln = ln
	s.conns = map[*net.UnixConn]struct{}{}
	return nil
}

// serve runs the accept loop until ctx is cancelled or the listener closes. Each
// accepted connection is handled on its own goroutine. A cancelled context makes
// the loop exit cleanly rather than treat the close-induced accept error as a
// failure.
func (s *server) serve(ctx context.Context) {
	var wg sync.WaitGroup
	for {
		conn, err := s.ln.AcceptUnix()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				if !errors.Is(err, net.ErrClosed) {
					s.d.log.Error("accept failed", "err", err.Error())
				}
			}
			wg.Wait()
			return
		}
		s.track(conn)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.untrack(conn)
			defer conn.Close()
			s.handle(ctx, conn)
		}()
	}
}

// close shuts the listener and every live connection, unblocking the accept
// loop and any in-flight read. The socket file is removed.
func (s *server) close() {
	if s.ln != nil {
		s.ln.Close()
	}
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
}

func (s *server) track(c *net.UnixConn) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
}

func (s *server) untrack(c *net.UnixConn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// handle reads and dispatches one request on conn. It reads the frame header
// first, then runs the fetch or hook path. Any protocol-level error is logged
// and the connection dropped; a resolve or delivery error is reported to the
// client as a scrubbed WriteError and alerted through the sink.
func (s *server) handle(ctx context.Context, conn *net.UnixConn) {
	rt, err := wire.ReadRequestHeader(conn)
	if err != nil {
		s.d.log.Warn("bad request header", "err", err.Error())
		return
	}
	switch rt {
	case wire.RequestFetch:
		s.handleFetch(ctx, conn)
	case wire.RequestHook:
		s.handleHook(ctx, conn)
	}
}

// handleFetch runs the peer-authenticated client path. It authenticates the peer
// by SO_PEERCRED (failing closed on any ambiguity), resolves the caller's own
// plan from the labels the authenticator read, builds the caller's bundle, and
// serializes it, then destroys the bundle. A validation error yields a scrubbed
// WriteError to the client AND a skip-and-alert through the sink. The caller's
// arrival clears its client-timeout expectation.
func (s *server) handleFetch(ctx context.Context, conn *net.UnixConn) {
	id, err := s.d.auth.Authenticate(ctx, conn)
	if err != nil {
		// Fail closed on any auth ambiguity. The peer is not a resolvable
		// container, so we never guess an identity: refuse without disclosing why.
		s.d.log.Warn("peer authentication failed", "err", err.Error())
		_ = wire.WriteError(conn, "unauthenticated")
		return
	}

	// The caller's fetch arrived: clear its client-timeout expectation before any
	// resolve work, so even a caller whose plan fails validation is not also
	// flagged as a missing wrapper.
	s.d.tracker.arrived(id.ContainerID)

	plan, rerr := resolve.Resolve(resolve.Input{
		Labels:          id.Labels,
		ContainerID:     id.ContainerID,
		Service:         id.ServiceName,
		Config:          s.d.berm,
		DefaultDelivery: s.d.defDeliv,
	})
	if rerr != nil {
		reason := s.d.alertValidation(ctx, id.ContainerID, id.ServiceName, rerr)
		_ = wire.WriteError(conn, reason)
		return
	}
	if plan == nil {
		// A fetch from a container that is not berm-enabled. Refuse plainly.
		_ = wire.WriteError(conn, "container is not berm-enabled")
		return
	}

	dplan := plan.ToDelivery()
	bundle, err := delivery.BuildBundle(ctx, id.ServiceName, dplan, s.d.opener, s.d.now())
	if err != nil {
		reason := s.d.alertValidation(ctx, id.ContainerID, id.ServiceName, err)
		_ = wire.WriteError(conn, reason)
		return
	}
	defer bundle.Destroy()

	if err := wire.EncodeBundle(conn, bundle); err != nil {
		s.d.log.Error("encode bundle failed", "container", id.ContainerID, "err", err.Error())
		return
	}
	s.recordFromBundleManifest(id.ContainerID, bundle)
}

// handleHook runs the trusted-injector hook path. It reads the presented
// container id and the container's OCI annotations, and asks the hook handler to
// derive the identity, validate, resolve, and build that container's file bundle
// from those annotations (no runtime inspect: that would deadlock against the
// create the pre-start hook is blocking). A not-enabled or not-hook-mode
// container is a clean skip (logged, no alert); a validation error is
// skip-and-alert; a built bundle is serialized and recorded.
func (s *server) handleHook(ctx context.Context, conn *net.UnixConn) {
	cid, annotations, err := wire.ReadHookBody(conn)
	if err != nil {
		s.d.log.Warn("bad hook request", "err", err.Error())
		_ = wire.WriteError(conn, "bad hook request")
		return
	}

	bundle, err := s.d.hookd.Handle(ctx, cid, annotations, s.d.now())
	if err != nil {
		// A hook that fired for a non-berm or non-hook container is a benign
		// misconfiguration: refuse it without an alert storm. A genuine
		// validation or delivery error is alerted.
		if errors.Is(err, hookdNotEnabled) || errors.Is(err, hookdNotHookMode) {
			s.d.log.Info("hook skip", "container", cid, "reason", err.Error())
			_ = wire.WriteError(conn, "not a hook-mode berm container")
			return
		}
		reason := s.d.alertValidation(ctx, cid, "", err)
		_ = wire.WriteError(conn, reason)
		return
	}
	defer bundle.Destroy()

	if err := wire.EncodeBundle(conn, bundle); err != nil {
		s.d.log.Error("encode hook bundle failed", "container", cid, "err", err.Error())
		return
	}
	s.recordFromBundleManifest(cid, bundle)
}

// recordFromBundleManifest parses the non-secret manifest the bundle carries and
// records the injection in the staleness ledger. The manifest holds names,
// paths, and ciphertext hashes only, never a value, so parsing and recording it
// leaks nothing. A malformed manifest is logged and skipped rather than fatal:
// the secret was already delivered, and a ledger gap is a staleness-report
// concern, not a delivery failure.
func (s *server) recordFromBundleManifest(containerID string, bundle *wire.Bundle) {
	m, err := delivery.ParseManifest(bundle.Manifest)
	if err != nil {
		s.d.log.Error("parse delivered manifest for ledger failed", "container", containerID, "err", err.Error())
		return
	}
	s.d.recordInjection(m)
}
