// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package cli

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/tagwright/core/runtime"
)

// fakeRuntime is a minimal runtime.Runtime for the CLI tests. It answers List
// and Inspect from a registered container set; the lifecycle-control methods are
// unused here and return nil or ErrNotImplemented.
type fakeRuntime struct {
	mu         sync.Mutex
	containers map[string]runtime.Container
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{containers: map[string]runtime.Container{}}
}

func (r *fakeRuntime) add(c runtime.Container) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.containers[c.ID] = c
}

func (r *fakeRuntime) List(context.Context) ([]runtime.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]runtime.Container, 0, len(r.containers))
	for _, c := range r.containers {
		out = append(out, c)
	}
	return out, nil
}

func (r *fakeRuntime) Inspect(_ context.Context, id string) (runtime.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.containers[id]
	if !ok {
		return runtime.Container{}, os.ErrNotExist
	}
	return c, nil
}

func (r *fakeRuntime) Watch(context.Context) (<-chan runtime.Event, <-chan error) {
	return nil, nil
}
func (r *fakeRuntime) Exec(context.Context, string, runtime.ExecSpec) (*runtime.ExecHandle, error) {
	return nil, runtime.ErrNotImplemented
}
func (r *fakeRuntime) Stop(context.Context, string, int) error    { return nil }
func (r *fakeRuntime) Start(context.Context, string) error        { return nil }
func (r *fakeRuntime) Kill(context.Context, string, string) error { return nil }
func (r *fakeRuntime) Restart(context.Context, string) error      { return nil }
func (r *fakeRuntime) Close() error                               { return nil }

var _ runtime.Runtime = (*fakeRuntime)(nil)

// fakeHashSource returns a fixed ciphertext hash per source, standing in for the
// config-backed Opener without touching any file. It satisfies daemon.HashSource
// and never decrypts.
type fakeHashSource map[string]string

func (h fakeHashSource) SourceCipherHash(source string) (string, error) {
	if v, ok := h[source]; ok {
		return v, nil
	}
	return "sha256:unknown-" + source, nil
}

// assertNoValue fails if haystack contains any known secret value (length >= 4,
// to avoid coincidental short matches). It is the no-value invariant guard.
func assertNoValue(t *testing.T, what, haystack string, values ...string) {
	t.Helper()
	for _, v := range values {
		if len(v) >= 4 && strings.Contains(haystack, v) {
			t.Fatalf("%s leaked a secret value %q", what, v)
		}
	}
}
