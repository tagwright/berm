// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/delivery"
	"github.com/tagwright/berm/internal/peerauth"
	"github.com/tagwright/berm/internal/wire"
)

// syncBuffer is a concurrency-safe buffer for capturing the daemon log across
// the server's goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// testDaemon builds a daemon wired with the given runtime, opener, config,
// authenticator, and sink, listening on a temp socket, with a captured log. It
// returns the daemon, the socket path, the log buffer, and starts serving until
// the returned cancel is called.
func testDaemon(t *testing.T, rt runtime.Runtime, opener delivery.Opener, cfg *config.Config, auth Authenticator, sink Sink) (*Daemon, string, *syncBuffer, context.CancelFunc) {
	t.Helper()
	logBuf := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	sock := filepath.Join(t.TempDir(), "berm.sock")
	d, err := New(Config{
		Runtime:    rt,
		Berm:       cfg,
		Opener:     opener,
		Sink:       sink,
		Auth:       auth,
		SocketPath: sock,
		LedgerPath: filepath.Join(t.TempDir(), "ledger.json"),
		Clock:      func() time.Time { return time.Unix(1735689600, 0).UTC() },
		Logger:     log,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.server.listen(sock); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go d.server.serve(ctx)
	t.Cleanup(func() {
		cancel()
		d.server.close()
	})
	return d, sock, logBuf, cancel
}

// dialAndFetch connects to the socket, sends a fetch request, and returns the
// response bundle or the daemon's refusal error.
func dialAndFetch(t *testing.T, sock string) (*wire.Bundle, error) {
	t.Helper()
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := wire.WriteRequest(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return wire.ReadResponse(conn)
}

// dialAndHook connects and sends a hook request for containerID with the
// container's presented OCI annotations (its berm.* config), the way the trusted
// pre-start hook does.
func dialAndHook(t *testing.T, sock, containerID string, annotations map[string]string) (*wire.Bundle, error) {
	t.Helper()
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := wire.WriteHookRequest(conn, containerID, annotations); err != nil {
		t.Fatalf("write hook request: %v", err)
	}
	return wire.ReadResponse(conn)
}

func TestServerFetchDispatch(t *testing.T) {
	const (
		dbPass   = "p=ss w0rd!"
		apiToken = "tok-abcdef0123456789"
		otherVal = "other-service-only-secret"
	)
	opener, cfg := realOpener(t,
		sopsSource{
			name:   "webapp",
			format: backend.FormatDotenv,
			dotenv: []kv{{"DB_PASSWORD", dbPass}, {"API_TOKEN", apiToken}},
		},
		// A source webapp does not reference and may not read, to prove scoping.
		sopsSource{
			name:   "other-db",
			owner:  "postgres",
			format: backend.FormatDotenv,
			dotenv: []kv{{"SECRET", otherVal}},
		},
	)

	labels := map[string]string{
		"berm.enable":           "true",
		"berm.delivery":         "client",
		"berm.file.pgpass.from": "DB_PASSWORD",
		"berm.env.API_TOKEN":    "API_TOKEN",
		"berm.env.acknowledge":  "true",
	}
	auth := &stubAuth{id: &peerauth.Identity{
		ContainerID: "cid-webapp",
		ServiceName: "webapp",
		Labels:      labels,
	}}

	d, sock, logBuf, _ := testDaemon(t, newFakeRuntime(), opener, cfg, auth, &fakeSink{})

	bundle, err := dialAndFetch(t, sock)
	if err != nil {
		t.Fatalf("fetch refused: %v", err)
	}
	defer bundle.Destroy()

	// File is byte-correct and at the declared path.
	if len(bundle.Files) != 1 {
		t.Fatalf("want 1 file, got %d", len(bundle.Files))
	}
	f := bundle.Files[0]
	if f.Path != "/run/berm/pgpass" {
		t.Errorf("file path = %q, want /run/berm/pgpass", f.Path)
	}
	if string(f.Data) != dbPass {
		t.Errorf("file data = %q, want %q", f.Data, dbPass)
	}
	// Env is byte-correct.
	if len(bundle.Env) != 1 || bundle.Env[0].Name != "API_TOKEN" {
		t.Fatalf("want 1 env API_TOKEN, got %+v", bundle.Env)
	}
	if string(bundle.Env[0].Value) != apiToken {
		t.Errorf("env value = %q, want %q", bundle.Env[0].Value, apiToken)
	}
	// The _FILE pointer is auto-set and non-secret.
	if len(bundle.Pointers) != 1 || bundle.Pointers[0].Name != "DB_PASSWORD_FILE" || bundle.Pointers[0].Path != "/run/berm/pgpass" {
		t.Errorf("pointer = %+v, want DB_PASSWORD_FILE -> /run/berm/pgpass", bundle.Pointers)
	}
	// Scoped to the caller: another service's secret is absent from the manifest
	// and the logs.
	if bytes.Contains(bundle.Manifest, []byte("other-db")) {
		t.Error("bundle manifest names a source the caller did not declare")
	}
	assertNoValue(t, "daemon log", logBuf.String(), otherVal)
	if s := string(bundle.Manifest); len(s) == 0 {
		t.Error("bundle carries no manifest")
	}

	// The injection was recorded in the ledger (recorded asynchronously in the
	// handler goroutine right after the bundle is serialized, so poll for it).
	waitFor(t, time.Second, func() bool {
		_, ok := d.ledger.Record("cid-webapp")
		return ok
	}, "ledger did not record the fetch injection")
	rec, _ := d.ledger.Record("cid-webapp")
	if rec.Service != "webapp" {
		t.Errorf("ledger record service = %q, want webapp", rec.Service)
	}
	if _, ok := rec.Sources["webapp"]; !ok {
		t.Errorf("ledger record missing the webapp source hash: %+v", rec.Sources)
	}
}

// waitFor polls cond until it is true or the timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestServerHookDispatch(t *testing.T) {
	const tlsKey = "-----BEGIN KEY-----\nabc123def456\n-----END KEY-----\n"
	opener, cfg := realOpener(t,
		sopsSource{
			name:   "hookapp",
			format: backend.FormatDotenv,
			dotenv: []kv{{"TOKEN", "hook-token-value-9876"}},
		},
	)

	// The hook path does NOT inspect the container over the runtime (that would
	// deadlock against the create the pre-start hook blocks): the daemon resolves
	// from the annotations the hook presents. The fake runtime is present only to
	// build the daemon; its Inspect is not consulted on this path.
	rt := newFakeRuntime()
	_ = tlsKey

	_, sock, _, _ := testDaemon(t, rt, opener, cfg, &stubAuth{}, &fakeSink{})

	// berm.name identifies the container: the hook has no container name to fall
	// back on, so hook-mode config is presented as annotations including berm.name.
	ann := map[string]string{
		"berm.enable":        "true",
		"berm.name":          "hookapp",
		"berm.delivery":      "hook",
		"berm.file.tok.from": "TOKEN",
	}
	bundle, err := dialAndHook(t, sock, "cid-hookapp", ann)
	if err != nil {
		t.Fatalf("hook refused: %v", err)
	}
	defer bundle.Destroy()

	if len(bundle.Files) != 1 {
		t.Fatalf("want 1 file, got %d", len(bundle.Files))
	}
	if bundle.Files[0].Path != "/run/berm/tok" {
		t.Errorf("file path = %q, want /run/berm/tok", bundle.Files[0].Path)
	}
	if string(bundle.Files[0].Data) != "hook-token-value-9876" {
		t.Errorf("file data = %q, want the token", bundle.Files[0].Data)
	}
	// Hook mode is files only: no env.
	if len(bundle.Env) != 0 {
		t.Errorf("hook bundle carried env: %+v", bundle.Env)
	}
}

func TestServerValidationErrorAlertsNoValue(t *testing.T) {
	const ungrantedVal = "supersecret-ungranted-value-42"
	opener, cfg := realOpener(t,
		sopsSource{
			name:   "webapp",
			format: backend.FormatDotenv,
			dotenv: []kv{{"DB_PASSWORD", "webapp-own-secret-1234"}},
		},
		// Owned by postgres, no grant to webapp: an ungranted (sticky) reference.
		sopsSource{
			name:   "other-db",
			owner:  "postgres",
			format: backend.FormatDotenv,
			dotenv: []kv{{"SECRET", ungrantedVal}},
		},
	)

	labels := map[string]string{
		"berm.enable":      "true",
		"berm.delivery":    "client",
		"berm.file.x.from": "other-db/SECRET", // ungranted cross-service ref
	}
	auth := &stubAuth{id: &peerauth.Identity{
		ContainerID: "cid-webapp",
		ServiceName: "webapp",
		Labels:      labels,
	}}

	sink := &fakeSink{}
	d, sock, logBuf, _ := testDaemon(t, newFakeRuntime(), opener, cfg, auth, sink)

	bundle, err := dialAndFetch(t, sock)
	if err == nil {
		bundle.Destroy()
		t.Fatal("want a refusal for an ungranted reference, got a bundle")
	}

	// An alert was raised.
	if sink.count() == 0 {
		t.Fatal("validation error raised no alert on the sink")
	}
	got := sink.all()[0]
	if got.Fields["class"] != "ungranted_ref" {
		t.Errorf("alert class = %q, want ungranted_ref", got.Fields["class"])
	}
	// It is sticky: the digest holds it.
	if len(d.sticky.list()) != 1 {
		t.Errorf("sticky store holds %d, want 1", len(d.sticky.list()))
	}
	// No secret value anywhere: the refusal happens before any decrypt, so the
	// ungranted source's value never touches the wire, the alert, or the logs.
	assertNoValue(t, "wire refusal", err.Error(), ungrantedVal)
	assertNoValue(t, "alert", sink.text(), ungrantedVal)
	assertNoValue(t, "daemon log", logBuf.String(), ungrantedVal)
}
