// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package peerauth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tagwright/core/runtime"
)

// fakeRuntime is a minimal runtime.Runtime whose only live method is Inspect.
// The rest return runtime.ErrNotImplemented, since the resolver never calls
// them.
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
func (f *fakeRuntime) Stop(context.Context, string, int) error   { return runtime.ErrNotImplemented }
func (f *fakeRuntime) Start(context.Context, string) error       { return runtime.ErrNotImplemented }
func (f *fakeRuntime) Kill(context.Context, string, string) error { return runtime.ErrNotImplemented }
func (f *fakeRuntime) Restart(context.Context, string) error     { return runtime.ErrNotImplemented }
func (f *fakeRuntime) Close() error                              { return nil }

var _ runtime.Runtime = (*fakeRuntime)(nil)

// writeProc lays down a fixture /proc/<pid>/{cgroup,stat} under root.
func writeProc(t *testing.T, root string, pid uint32, cgroup, stat string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if cgroup != "" {
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if stat != "" {
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func newTestAuth(procRoot string, f *fakeRuntime) *Authenticator {
	return &Authenticator{rt: f, procRoot: procRoot}
}

func TestResolveHappyPath(t *testing.T) {
	root := t.TempDir()
	const pid = 4321
	writeProc(t, root, pid,
		"0::/system.slice/docker-"+idA+".scope\n",
		statSimple,
	)

	f := &fakeRuntime{inspect: func(_ context.Context, id string) (runtime.Container, error) {
		if id != idA {
			t.Fatalf("expected inspect of %s, got %s", idA, id)
		}
		return runtime.Container{
			ID:      idA,
			Name:    "myproj-webapp-1",
			Service: "webapp",
			Labels:  map[string]string{"berm.enable": "true"},
		}, nil
	}}

	a := newTestAuth(root, f)
	got, err := a.resolve(context.Background(), Ucred{PID: pid, UID: 1000, GID: 1000})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.ContainerID != idA {
		t.Errorf("container id: want %s got %s", idA, got.ContainerID)
	}
	if got.ServiceName != "webapp" {
		t.Errorf("service: want webapp got %s", got.ServiceName)
	}
	if got.Pin.PID != pid || got.Pin.StartTime != 8967 {
		t.Errorf("pin: want {%d 8967} got %+v", pid, got.Pin)
	}
	if got.Cred.UID != 1000 {
		t.Errorf("cred uid: want 1000 got %d", got.Cred.UID)
	}
}

func TestResolveBermNameOverride(t *testing.T) {
	root := t.TempDir()
	const pid = 77
	writeProc(t, root, pid, "0::/docker/"+idA+"\n", statSimple)

	f := &fakeRuntime{inspect: func(_ context.Context, _ string) (runtime.Container, error) {
		return runtime.Container{
			ID:      idA,
			Name:    "c",
			Service: "composed",
			Labels:  map[string]string{"berm.name": "override-identity"},
		}, nil
	}}
	got, err := newTestAuth(root, f).resolve(context.Background(), Ucred{PID: pid})
	if err != nil {
		t.Fatal(err)
	}
	if got.ServiceName != "override-identity" {
		t.Fatalf("berm.name should win: got %s", got.ServiceName)
	}
}

func TestResolveServiceNameFallbackToContainerName(t *testing.T) {
	root := t.TempDir()
	const pid = 78
	writeProc(t, root, pid, "0::/docker/"+idA+"\n", statSimple)
	f := &fakeRuntime{inspect: func(_ context.Context, _ string) (runtime.Container, error) {
		return runtime.Container{ID: idA, Name: "bare-container"}, nil
	}}
	got, err := newTestAuth(root, f).resolve(context.Background(), Ucred{PID: pid})
	if err != nil {
		t.Fatal(err)
	}
	if got.ServiceName != "bare-container" {
		t.Fatalf("want container-name fallback, got %s", got.ServiceName)
	}
}

func TestResolveFailClosed(t *testing.T) {
	t.Run("missing cgroup file", func(t *testing.T) {
		root := t.TempDir()
		const pid = 5
		// stat present, cgroup absent
		writeProc(t, root, pid, "", statSimple)
		f := &fakeRuntime{inspect: func(context.Context, string) (runtime.Container, error) {
			t.Fatal("inspect must not be reached")
			return runtime.Container{}, nil
		}}
		if _, err := newTestAuth(root, f).resolve(context.Background(), Ucred{PID: pid}); err == nil {
			t.Fatal("want error on missing cgroup")
		}
	})

	t.Run("missing stat file", func(t *testing.T) {
		root := t.TempDir()
		const pid = 6
		writeProc(t, root, pid, "0::/docker/"+idA+"\n", "")
		f := &fakeRuntime{inspect: func(context.Context, string) (runtime.Container, error) {
			t.Fatal("inspect must not be reached: start-time pin comes first")
			return runtime.Container{}, nil
		}}
		if _, err := newTestAuth(root, f).resolve(context.Background(), Ucred{PID: pid}); err == nil {
			t.Fatal("want error on missing stat")
		}
	})

	t.Run("no container id in cgroup", func(t *testing.T) {
		root := t.TempDir()
		const pid = 7
		writeProc(t, root, pid, "0::/\n", statSimple)
		f := &fakeRuntime{inspect: func(context.Context, string) (runtime.Container, error) {
			t.Fatal("inspect must not be reached")
			return runtime.Container{}, nil
		}}
		if _, err := newTestAuth(root, f).resolve(context.Background(), Ucred{PID: pid}); err == nil {
			t.Fatal("want error when no id extractable")
		}
	})

	t.Run("inspect id mismatch", func(t *testing.T) {
		root := t.TempDir()
		const pid = 8
		writeProc(t, root, pid, "0::/docker/"+idA+"\n", statSimple)
		f := &fakeRuntime{inspect: func(context.Context, string) (runtime.Container, error) {
			// Runtime resolves to a DIFFERENT id than the cgroup carried.
			return runtime.Container{ID: idB, Name: "wrong"}, nil
		}}
		if _, err := newTestAuth(root, f).resolve(context.Background(), Ucred{PID: pid}); err == nil {
			t.Fatal("want error on inspect id mismatch")
		}
	})

	t.Run("inspect error", func(t *testing.T) {
		root := t.TempDir()
		const pid = 9
		writeProc(t, root, pid, "0::/docker/"+idA+"\n", statSimple)
		f := &fakeRuntime{inspect: func(context.Context, string) (runtime.Container, error) {
			return runtime.Container{}, fmt.Errorf("no such container")
		}}
		if _, err := newTestAuth(root, f).resolve(context.Background(), Ucred{PID: pid}); err == nil {
			t.Fatal("want error when inspect fails")
		}
	})

	t.Run("conflicting berm.name across prefixes", func(t *testing.T) {
		root := t.TempDir()
		const pid = 10
		writeProc(t, root, pid, "0::/docker/"+idA+"\n", statSimple)
		f := &fakeRuntime{inspect: func(context.Context, string) (runtime.Container, error) {
			return runtime.Container{
				ID:   idA,
				Name: "c",
				Labels: map[string]string{
					"berm.name":            "one",
					"tagwright.secret.name": "two",
				},
			}, nil
		}}
		if _, err := newTestAuth(root, f).resolve(context.Background(), Ucred{PID: pid}); err == nil {
			t.Fatal("want error on conflicting berm.name")
		}
	})
}

func TestVerifyPin(t *testing.T) {
	root := t.TempDir()
	const pid = 999
	writeProc(t, root, pid, "0::/docker/"+idA+"\n", statSimple)
	f := &fakeRuntime{inspect: func(context.Context, string) (runtime.Container, error) {
		return runtime.Container{ID: idA, Name: "c", Service: "svc"}, nil
	}}
	a := newTestAuth(root, f)
	id, err := a.resolve(context.Background(), Ucred{PID: pid})
	if err != nil {
		t.Fatal(err)
	}

	// Same start-time: verify passes.
	if err := a.Verify(id); err != nil {
		t.Fatalf("verify should pass with matching pin: %v", err)
	}

	// Simulate pid reuse: same pid, different start-time in stat.
	reused := "999 (other) S 1 999 999 0 -1 4194304 1 0 0 0 0 0 0 0 20 0 1 0 123456 0 0"
	writeProc(t, root, pid, "0::/docker/"+idA+"\n", reused)
	if err := a.Verify(id); err == nil {
		t.Fatal("verify must reject a reused pid (start-time changed)")
	}

	// Peer gone: stat missing, verify fails closed.
	if err := os.Remove(filepath.Join(root, "999", "stat")); err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(id); err == nil {
		t.Fatal("verify must fail closed when the process is gone")
	}

	// Nil identity.
	if err := a.Verify(nil); err == nil {
		t.Fatal("verify(nil) must error")
	}
}
