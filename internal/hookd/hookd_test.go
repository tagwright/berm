// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package hookd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/delivery"
)

// --- fake opener over one in-memory dotenv source --------------------------

type fakeOpener struct{}

func (fakeOpener) OpenSource(_ context.Context, source string) (backend.Opened, error) {
	if source != "webapp" {
		return nil, errors.New("fake: no such source " + source)
	}
	return &fakeOpened{}, nil
}
func (fakeOpener) SourceCipherHash(source string) (string, error) {
	if source != "webapp" {
		return "", errors.New("fake: no such source " + source)
	}
	return "sha256:1111111111111111111111111111111111111111111111111111111111111111", nil
}

type fakeOpened struct{}

func (fakeOpened) Format() backend.SourceFormat { return backend.FormatDotenv }
func (fakeOpened) Keys() ([]string, error)      { return []string{"DB_PASSWORD"}, nil }
func (fakeOpened) Value(k string) ([]byte, error) {
	if k == "DB_PASSWORD" {
		return []byte("p=ss w0rd!"), nil
	}
	return nil, backend.ErrNoSuchKey
}
func (fakeOpened) WriteValue(w io.Writer, k string) (int64, error) {
	v, err := fakeOpened{}.Value(k)
	if err != nil {
		return 0, err
	}
	n, err := w.Write(v)
	return int64(n), err
}
func (fakeOpened) Payload() ([]byte, error)              { return nil, backend.ErrWrongFormat }
func (fakeOpened) WritePayload(io.Writer) (int64, error) { return 0, backend.ErrWrongFormat }
func (fakeOpened) Close() error                          { return nil }

func testConfig() *config.Config {
	return &config.Config{
		Sources: map[string]config.Source{
			"webapp": {Format: "dotenv"},
		},
	}
}

// The daemon default delivery in these tests is hook, matching a Podman daemon.
func newHandler() *Handler {
	return NewHandler(testConfig(), fakeOpener{}, delivery.MechHook)
}

const cid = "3f1a2b9c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8"

// TestHandleResolvesFromPresentedAnnotations proves the deadlock-fix contract:
// the handler builds the bundle purely from the OCI annotations the hook
// presented, with NO runtime inspect (the handler holds no runtime at all).
func TestHandleResolvesFromPresentedAnnotations(t *testing.T) {
	h := newHandler()
	ann := map[string]string{
		"berm.enable":           "true",
		"berm.name":             "webapp",
		"berm.file.pgpass.from": "DB_PASSWORD",
		// No berm.delivery: falls to the daemon default, hook.
		// A stray non-berm annotation must be ignored, not an error.
		"io.container.manager": "libpod",
	}

	b, err := h.Handle(context.Background(), cid, ann, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	defer b.Destroy()

	if len(b.Files) != 1 {
		t.Fatalf("files = %d, want 1", len(b.Files))
	}
	if b.Files[0].Path != "/run/berm/pgpass" {
		t.Errorf("file path = %q", b.Files[0].Path)
	}
	if !bytes.Equal(b.Files[0].Data, []byte("p=ss w0rd!")) {
		t.Errorf("file data = %q", b.Files[0].Data)
	}
	if len(b.Env) != 0 {
		t.Errorf("hook bundle must carry no env, got %d", len(b.Env))
	}
	if len(b.Manifest) == 0 {
		t.Fatal("manifest missing")
	}
	if bytes.Contains(b.Manifest, []byte("p=ss w0rd!")) {
		t.Error("manifest leaked a value")
	}
	for _, want := range []string{"DB_PASSWORD_FILE", "sha256:1111", "/run/berm/pgpass"} {
		if !bytes.Contains(b.Manifest, []byte(want)) {
			t.Errorf("manifest missing %q:\n%s", want, b.Manifest)
		}
	}
}

// TestHandleIdentityFromComposeAnnotation proves a hook-mode container with no
// berm.name is identified by its compose-service annotation (the hook has no
// container name to fall back on).
func TestHandleIdentityFromComposeAnnotation(t *testing.T) {
	h := newHandler()
	ann := map[string]string{
		"berm.enable":                "true",
		"berm.delivery":              "hook",
		"com.docker.compose.service": "webapp",
		"com.docker.compose.project": "myproj",
		"berm.file.pgpass.from":      "DB_PASSWORD",
	}
	b, err := h.Handle(context.Background(), cid, ann, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	defer b.Destroy()
	if len(b.Files) != 1 || !bytes.Equal(b.Files[0].Data, []byte("p=ss w0rd!")) {
		t.Fatalf("expected webapp's secret resolved via the compose annotation, got %+v", b.Files)
	}
}

// TestHandleNoIdentityFails proves a hook-mode container with neither a berm.name
// nor a compose-service annotation fails closed (the hook has no container name).
func TestHandleNoIdentityFails(t *testing.T) {
	h := newHandler()
	ann := map[string]string{
		"berm.enable":           "true",
		"berm.delivery":         "hook",
		"berm.file.pgpass.from": "DB_PASSWORD",
	}
	if _, err := h.Handle(context.Background(), cid, ann, time.Now()); err == nil {
		t.Fatal("expected a failure with no resolvable service identity")
	}
}

func TestHandleRefusesEnv(t *testing.T) {
	// A hook-mode container that declares env is refused: env is impossible in
	// hook mode. The resolver rejects it; Handle surfaces the error.
	h := newHandler()
	ann := map[string]string{
		"berm.enable":          "true",
		"berm.name":            "webapp",
		"berm.delivery":        "hook",
		"berm.env":             "DB_PASSWORD",
		"berm.env.acknowledge": "true",
	}
	if _, err := h.Handle(context.Background(), cid, ann, time.Now()); err == nil {
		t.Fatal("expected env on hook mode to be refused")
	}
}

func TestHandleRefusesInert(t *testing.T) {
	// A container without berm.enable is inert; a hook request for it is refused.
	h := newHandler()
	ann := map[string]string{"berm.name": "webapp"}
	_, err := h.Handle(context.Background(), cid, ann, time.Now())
	if !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("Handle inert = %v, want ErrNotEnabled", err)
	}
}

func TestHandleRefusesNonHookMechanism(t *testing.T) {
	// A berm container that chose client-mode must not be injected by the hook.
	h := newHandler()
	ann := map[string]string{
		"berm.enable":           "true",
		"berm.name":             "webapp",
		"berm.delivery":         "client",
		"berm.file.pgpass.from": "DB_PASSWORD",
	}
	_, err := h.Handle(context.Background(), cid, ann, time.Now())
	if !errors.Is(err, ErrNotHookMode) {
		t.Fatalf("Handle client-mode = %v, want ErrNotHookMode", err)
	}
}
