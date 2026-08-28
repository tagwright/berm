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

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/delivery"
)

// --- fake runtime: only Inspect is live ------------------------------------

type fakeRuntime struct {
	inspect func(ctx context.Context, id string) (runtime.Container, error)
}

func (f *fakeRuntime) List(context.Context) ([]runtime.Container, error) {
	return nil, runtime.ErrNotImplemented
}
func (f *fakeRuntime) Inspect(ctx context.Context, id string) (runtime.Container, error) {
	return f.inspect(ctx, id)
}
func (f *fakeRuntime) Watch(context.Context) (<-chan runtime.Event, <-chan error) { return nil, nil }
func (f *fakeRuntime) Exec(context.Context, string, runtime.ExecSpec) (*runtime.ExecHandle, error) {
	return nil, runtime.ErrNotImplemented
}
func (f *fakeRuntime) Stop(context.Context, string, int) error    { return runtime.ErrNotImplemented }
func (f *fakeRuntime) Start(context.Context, string) error        { return runtime.ErrNotImplemented }
func (f *fakeRuntime) Kill(context.Context, string, string) error { return runtime.ErrNotImplemented }
func (f *fakeRuntime) Restart(context.Context, string) error      { return runtime.ErrNotImplemented }
func (f *fakeRuntime) Close() error                               { return nil }

var _ runtime.Runtime = (*fakeRuntime)(nil)

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

func newHandler(inspect func(ctx context.Context, id string) (runtime.Container, error)) *Handler {
	return NewHandler(&fakeRuntime{inspect: inspect}, testConfig(), fakeOpener{}, delivery.MechHook)
}

const cid = "3f1a2b9c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8"

func TestHandleReturnsFileBundle(t *testing.T) {
	h := newHandler(func(_ context.Context, id string) (runtime.Container, error) {
		if id != cid {
			t.Fatalf("inspect id = %q, want %q", id, cid)
		}
		return runtime.Container{
			ID:      cid,
			Name:    "myproj-webapp-1",
			Service: "webapp",
			Labels: map[string]string{
				"berm.enable":           "true",
				"berm.file.pgpass.from": "DB_PASSWORD",
				// No berm.delivery: falls to the daemon default, hook.
			},
		}, nil
	})

	b, err := h.Handle(context.Background(), cid, time.Unix(1_700_000_000, 0))
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
	// Files only: no env in a hook bundle.
	if len(b.Env) != 0 {
		t.Errorf("hook bundle must carry no env, got %d", len(b.Env))
	}
	// Manifest present, records the pointer and hash, never a value.
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

func TestHandleRefusesEnv(t *testing.T) {
	// A hook-mode container that declares env is refused: env is impossible in
	// hook mode. The resolver rejects it; Handle surfaces the error.
	h := newHandler(func(context.Context, string) (runtime.Container, error) {
		return runtime.Container{
			ID:      cid,
			Service: "webapp",
			Labels: map[string]string{
				"berm.enable":          "true",
				"berm.delivery":        "hook",
				"berm.env":             "DB_PASSWORD",
				"berm.env.acknowledge": "true",
			},
		}, nil
	})
	if _, err := h.Handle(context.Background(), cid, time.Now()); err == nil {
		t.Fatal("expected env on hook mode to be refused")
	}
}

func TestHandleRefusesInert(t *testing.T) {
	// A container without berm.enable is inert; a hook request for it is refused.
	h := newHandler(func(context.Context, string) (runtime.Container, error) {
		return runtime.Container{ID: cid, Service: "webapp", Labels: map[string]string{}}, nil
	})
	_, err := h.Handle(context.Background(), cid, time.Now())
	if !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("Handle inert = %v, want ErrNotEnabled", err)
	}
}

func TestHandleRefusesNonHookMechanism(t *testing.T) {
	// A berm container that chose client-mode must not be injected by the hook.
	h := newHandler(func(context.Context, string) (runtime.Container, error) {
		return runtime.Container{
			ID:      cid,
			Service: "webapp",
			Labels: map[string]string{
				"berm.enable":           "true",
				"berm.delivery":         "client",
				"berm.file.pgpass.from": "DB_PASSWORD",
			},
		}, nil
	})
	_, err := h.Handle(context.Background(), cid, time.Now())
	if !errors.Is(err, ErrNotHookMode) {
		t.Fatalf("Handle client-mode = %v, want ErrNotHookMode", err)
	}
}

func TestHandleInspectError(t *testing.T) {
	h := newHandler(func(context.Context, string) (runtime.Container, error) {
		return runtime.Container{}, errors.New("no such container")
	})
	if _, err := h.Handle(context.Background(), cid, time.Now()); err == nil {
		t.Fatal("expected an error when inspect fails")
	}
}
