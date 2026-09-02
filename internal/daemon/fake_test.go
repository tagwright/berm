// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tagwright/beacon"
	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/delivery"
	"github.com/tagwright/berm/internal/peerauth"
)

// --- fake runtime -----------------------------------------------------------

// fakeRuntime is a minimal runtime.Runtime for the daemon tests. It answers
// List and Inspect from a registered container set and streams synthetic
// lifecycle events through a channel the test feeds. The lifecycle-control
// methods are unused by these tests and return nil or ErrNotImplemented.
type fakeRuntime struct {
	mu         sync.Mutex
	containers map[string]runtime.Container
	events     chan runtime.Event
	errs       chan error
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{
		containers: map[string]runtime.Container{},
		events:     make(chan runtime.Event, 16),
		errs:       make(chan error, 1),
	}
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
	return r.events, r.errs
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

// --- fake sink --------------------------------------------------------------

// captured is one alert the fake sink recorded.
type captured struct {
	Level  beacon.Level
	Title  string
	Body   string
	Fields map[string]string
}

// fakeSink records every alert for assertion. It is safe for concurrent use so
// timer-driven alerts (the client-timeout tracker) can land on it.
type fakeSink struct {
	mu     sync.Mutex
	alerts []captured
}

func (s *fakeSink) Alert(_ context.Context, level beacon.Level, title, body string, fields map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := map[string]string{}
	for k, v := range fields {
		cp[k] = v
	}
	s.alerts = append(s.alerts, captured{Level: level, Title: title, Body: body, Fields: cp})
	return nil
}

func (s *fakeSink) all() []captured {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]captured(nil), s.alerts...)
}

func (s *fakeSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.alerts)
}

// text returns every recorded alert flattened to one string, for no-leak greps.
func (s *fakeSink) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for _, a := range s.alerts {
		b.WriteString(a.Title)
		b.WriteByte('\n')
		b.WriteString(a.Body)
		b.WriteByte('\n')
		for k, v := range a.Fields {
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

var _ Sink = (*fakeSink)(nil)

// --- stub authenticator -----------------------------------------------------

// stubAuth returns a fixed identity regardless of the connection, standing in
// for the real SO_PEERCRED walk (which needs a real peer container). The live
// peer-auth path is proven in the peerauth chunk and re-proven live in the
// integration chunk; here a test injects the identity the walk would have
// produced so the socket-server dispatch can be exercised in-process.
type stubAuth struct {
	id  *peerauth.Identity
	err error
}

func (a *stubAuth) Authenticate(context.Context, *net.UnixConn) (*peerauth.Identity, error) {
	if a.err != nil {
		return nil, a.err
	}
	return a.id, nil
}

var _ Authenticator = (*stubAuth)(nil)

// --- real sops/age opener ---------------------------------------------------

// sopsSource is one source to seed into the real-backend opener: a name, a
// format, and its known plaintext (dotenv pairs or a binary payload).
type sopsSource struct {
	name    string
	owner   string
	access  []string
	format  backend.SourceFormat
	dotenv  []kv
	payload []byte
}

type kv struct {
	key   string
	value string
}

// realOpener builds a delivery.Opener over the true SOPS/age backend, encrypting
// each source with a freshly generated age key. It skips the test when sops or
// age are not on PATH, so the daemon dispatch tests run for real where the
// pinned binaries are installed and skip cleanly where they are not. It returns
// the opener and the loaded config so a test can resolve against the same view.
func realOpener(t *testing.T, sources ...sopsSource) (delivery.Opener, *config.Config) {
	t.Helper()
	requireTool(t, "sops")
	requireTool(t, "age-keygen")

	dir := t.TempDir()
	keyPath, recipient := genAgeKey(t, dir, "default.key")

	cfg := &config.Config{
		AgeKeys: map[string]string{"default": keyPath},
		Sources: map[string]config.Source{},
	}
	for _, s := range sources {
		var plaintext []byte
		sopsType := "dotenv"
		if s.format == backend.FormatBinary {
			sopsType = "binary"
			plaintext = s.payload
		} else {
			var b bytes.Buffer
			for _, p := range s.dotenv {
				b.WriteString(p.key)
				b.WriteByte('=')
				b.WriteString(p.value)
				b.WriteByte('\n')
			}
			plaintext = b.Bytes()
		}
		out := filepath.Join(dir, s.name+".sops."+shortExt(s.format))
		sopsEncrypt(t, dir, recipient, sopsType, plaintext, out)
		cfg.Sources[s.name] = config.Source{
			File:   out,
			Format: string(s.format),
			Owner:  s.owner,
			Access: s.access,
		}
	}

	be := backend.NewSOPSAge(cfg.AgeKeys)
	return delivery.NewConfigOpener(cfg, be), cfg
}

func shortExt(f backend.SourceFormat) string {
	if f == backend.FormatBinary {
		return "bin"
	}
	return "env"
}

// requireTool skips the test if the named binary is not on PATH.
func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("daemon dispatch test needs %q on PATH: %v", name, err)
	}
}

// genAgeKey writes a fresh age keypair and returns the key path and recipient.
func genAgeKey(t *testing.T, dir, name string) (keyPath, recipient string) {
	t.Helper()
	keyPath = filepath.Join(dir, name)
	cmd := exec.Command("age-keygen", "-o", keyPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("age-keygen: %v: %s", err, stderr.String())
	}
	f, err := os.Open(keyPath)
	if err != nil {
		t.Fatalf("open age key: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(strings.ToLower(line), "# public key:") {
			recipient = strings.TrimSpace(line[strings.IndexByte(line, ':')+1:])
		}
	}
	if recipient == "" {
		t.Fatal("could not parse age recipient from key file")
	}
	return keyPath, recipient
}

// sopsEncrypt encrypts plaintext to outPath using a .sops.yaml naming recipient.
func sopsEncrypt(t *testing.T, dir, recipient, sopsType string, plaintext []byte, outPath string) {
	t.Helper()
	rule := "creation_rules:\n  - path_regex: .*\n    age: " + recipient + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".sops.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}
	plainPath := filepath.Join(dir, "plain."+sopsType+".in")
	if err := os.WriteFile(plainPath, plaintext, 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	cmd := exec.Command("sops", "-e", "--input-type", sopsType, "--output-type", sopsType, plainPath)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sops encrypt: %v: %s", err, stderr.String())
	}
	if err := os.WriteFile(outPath, out.Bytes(), 0o600); err != nil {
		t.Fatalf("write ciphertext: %v", err)
	}
}

// tmpfsDir returns a tmpfs-backed temp dir under /dev/shm, skipping the test if
// /dev/shm is not available (the volume path requires tmpfs).
func tmpfsDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/dev/shm", "berm-daemon-*")
	if err != nil {
		t.Skipf("volume test needs a tmpfs at /dev/shm: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// assertNoValue fails if haystack contains any of the secret values. Values
// under 4 bytes are skipped to avoid coincidental matches.
func assertNoValue(t *testing.T, what, haystack string, values ...string) {
	t.Helper()
	for _, v := range values {
		if len(v) >= 4 && strings.Contains(haystack, v) {
			t.Fatalf("%s leaked a secret value %q", what, v)
		}
	}
}
