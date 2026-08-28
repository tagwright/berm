// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Package daemon is berm's long-lived control plane: the piece that holds the
// age key, watches the container runtime, and hands each container only its own
// declared secrets. It ties together everything the earlier chunks built, the
// peer authenticator, the resolver, the backend, the three delivery mechanisms,
// the hook handler, and the beacon alert sink, behind one socket server and one
// event-driven control loop.
//
// Security contract (the spine, restated at the layer that enforces it). The
// daemon holds the age key by PATH only (provisioned at deploy, read by the
// sops subprocess, never by this process). It holds no secret at rest: the only
// plaintext window is the transient resolve-and-deliver step, guarded by
// memguard and zeroized best-effort after every bundle is serialized. It never
// logs a secret value on any path. The staleness ledger stores ciphertext
// hashes, names, paths, and timestamps only, never a value, which is why it may
// persist to a small non-secret file. The daemon makes no outbound network call:
// its only I/O is the local runtime socket, the local berm socket it listens on,
// the local ciphertext and key files, and the beacon sink the operator
// configures.
package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/tagwright/beacon"
	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/alert"
	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/delivery"
	"github.com/tagwright/berm/internal/hookd"
	"github.com/tagwright/berm/internal/label"
	"github.com/tagwright/berm/internal/peerauth"
)

// Sink is the beacon-backed diagnostics seam (alert.Sink). It reports names,
// reasons, and severities only, never a secret value. It is aliased here so the
// daemon's own signatures read in one vocabulary.
type Sink = alert.Sink

// hookdNotEnabled and hookdNotHookMode alias the hook handler's benign-skip
// sentinels, so the server can tell a hook that fired for a non-berm or
// non-hook-mode container (a clean skip) from a genuine validation failure (a
// skip-and-alert).
var (
	hookdNotEnabled  = hookd.ErrNotEnabled
	hookdNotHookMode = hookd.ErrNotHookMode
)

// DefaultSocketPath is the berm listen socket the client and hook connect to.
const DefaultSocketPath = "/run/berm/berm.sock"

// DefaultLedgerPath is where the staleness ledger persists. It holds ciphertext
// hashes and names only, never a value, so it is a non-secret file.
const DefaultLedgerPath = "/var/lib/berm/ledger.json"

// DefaultVolumeMountRoot is the daemon-side root under which each volume-mode
// container's shared tmpfs named volume is mounted. The daemon-side path for a
// volume named berm-<service> is <root>/berm-<service>. The deploy config
// mounts the volumes here.
const DefaultVolumeMountRoot = "/run/berm/volumes"

// DefaultReconcileInterval is how often the daemon reconciles volume-mode
// containers whose shared volume is missing its manifest. This closes the
// create-then-gated-start gap in the volume deploy topology (see runReconcile),
// where a container is created but its start is blocked by the manifest waiter,
// so no start event ever fires to trigger population.
const DefaultReconcileInterval = 2 * time.Second

// Authenticator authenticates a caller on the berm socket to a container
// identity. *peerauth.Authenticator satisfies it. It is an interface so a
// library-level test can inject a stubbed identity in place of a live
// SO_PEERCRED walk (which needs a real peer). The live SO_PEERCRED path is
// proven in the peerauth chunk and re-proven live in the integration chunk.
type Authenticator interface {
	Authenticate(ctx context.Context, conn *net.UnixConn) (*peerauth.Identity, error)
}

// Config is everything the daemon needs, wired by cmd/berm from a loaded
// berm.yml and the selected runtime. Nothing here is a secret value.
type Config struct {
	// Runtime is the selected container runtime (Docker or Podman).
	Runtime runtime.Runtime

	// Berm is the loaded berm.yml plus the BERM_* globals.
	Berm *config.Config

	// Opener resolves a source name to a decrypt handle and to its ciphertext
	// hash. The daemon builds a delivery.NewConfigOpener over the backend.
	Opener delivery.Opener

	// Sink is the beacon-backed alert sink. A nil sink disables alerting (used
	// by tests that do not assert on alerts).
	Sink Sink

	// Auth authenticates socket peers. Nil defaults to peerauth.New(Runtime).
	Auth Authenticator

	// DefaultDelivery is the effective BERM_DEFAULT_DELIVERY the daemon resolved
	// per runtime. Empty lets New resolve it from Berm.Globals and the runtime.
	DefaultDelivery delivery.Mechanism

	// SocketPath is the berm listen socket. Empty uses DefaultSocketPath.
	SocketPath string

	// LedgerPath is the staleness ledger file. Empty uses DefaultLedgerPath.
	LedgerPath string

	// VolumeMountRoot is the daemon-side root for volume-mode named volumes.
	// Empty uses DefaultVolumeMountRoot.
	VolumeMountRoot string

	// ClientTimeout is the client-mode fetch deadline. Zero uses
	// Berm.Globals.ClientTimeout.
	ClientTimeout time.Duration

	// ReconcileInterval is how often the volume-mode reconcile runs. Zero uses
	// DefaultReconcileInterval. A negative value disables the reconcile (used by
	// tests that drive the loop deterministically).
	ReconcileInterval time.Duration

	// DigestEnabled turns the scheduled stale digest on. When false no digest is
	// scheduled. Defaults from Berm.Globals.StaleDigest when Berm is set.
	DigestEnabled bool

	// DigestSchedule is the digest cadence. Empty uses Berm.Globals.DigestSchedule.
	DigestSchedule string

	// Clock is the time source, injectable for tests. Nil uses time.Now.
	Clock func() time.Time

	// Logger is the operator-facing logger. It logs names, reasons, and errors,
	// never a secret value. Nil discards.
	Logger *slog.Logger
}

// Daemon is the running berm control plane: a socket server, an event-driven
// control loop, a staleness ledger, a client-timeout tracker, and a scheduled
// digest. Construct it with New and drive it with Run.
type Daemon struct {
	cfg            Config
	rt             runtime.Runtime
	berm           *config.Config
	opener         delivery.Opener
	sink           Sink
	auth           Authenticator
	hookd          *hookd.Handler
	ledger         *Ledger
	tracker        *clientTracker
	defDeliv       delivery.Mechanism
	sockPath       string
	volRoot        string
	reconcileEvery time.Duration
	log            *slog.Logger
	now            func() time.Time

	sticky *stickyStore
	locks  *keyedMutex

	server *server
}

// New builds a Daemon from cfg, applying defaults and reloading any persisted
// ledger. It does no I/O beyond reading the ledger file: the socket is bound and
// the loop started by Run.
func New(cfg Config) (*Daemon, error) {
	if cfg.Runtime == nil {
		return nil, errors.New("daemon: a runtime is required")
	}
	if cfg.Berm == nil {
		return nil, errors.New("daemon: a loaded berm.yml is required")
	}
	if cfg.Opener == nil {
		return nil, errors.New("daemon: a delivery opener is required")
	}

	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	auth := cfg.Auth
	if auth == nil {
		auth = peerauth.New(cfg.Runtime)
	}
	defDeliv := cfg.DefaultDelivery
	if defDeliv == "" {
		defDeliv = EffectiveDefaultDelivery(cfg.Berm)
	}
	sockPath := cfg.SocketPath
	if sockPath == "" {
		sockPath = DefaultSocketPath
	}
	ledgerPath := cfg.LedgerPath
	if ledgerPath == "" {
		ledgerPath = DefaultLedgerPath
	}
	volRoot := cfg.VolumeMountRoot
	if volRoot == "" {
		volRoot = DefaultVolumeMountRoot
	}
	timeout := cfg.ClientTimeout
	if timeout == 0 {
		timeout = cfg.Berm.Globals.ClientTimeout
	}
	reconcileEvery := cfg.ReconcileInterval
	if reconcileEvery == 0 {
		reconcileEvery = DefaultReconcileInterval
	}

	ledger, err := LoadLedger(ledgerPath)
	if err != nil {
		return nil, err
	}

	d := &Daemon{
		cfg:            cfg,
		rt:             cfg.Runtime,
		berm:           cfg.Berm,
		opener:         cfg.Opener,
		sink:           cfg.Sink,
		auth:           auth,
		hookd:          hookd.NewHandler(cfg.Berm, cfg.Opener, defDeliv),
		ledger:         ledger,
		defDeliv:       defDeliv,
		sockPath:       sockPath,
		volRoot:        volRoot,
		reconcileEvery: reconcileEvery,
		log:            log,
		now:            now,
		sticky:         newStickyStore(),
		locks:          newKeyedMutex(),
	}
	d.tracker = newClientTracker(context.Background(), timeout, cfg.Sink)
	d.server = &server{d: d}
	return d, nil
}

// Ledger exposes the staleness ledger, so cmd/berm and the CLI chunk can run the
// `berm stale` drift query against the same in-memory ledger a running daemon
// keeps, and so a standalone process can load it from disk with LoadLedger.
func (d *Daemon) Ledger() *Ledger { return d.ledger }

// Run starts the socket server, the control loop, and (when enabled) the digest
// scheduler, then blocks until ctx is cancelled, at which point it shuts every
// piece down cleanly and returns. It is the daemon's public entrypoint: cmd/berm
// wires SIGINT/SIGTERM to the ctx it passes here.
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.server.listen(d.sockPath); err != nil {
		return err
	}
	d.log.Info("berm daemon started",
		"socket", d.sockPath,
		"runtime_default_delivery", string(d.defDeliv))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); d.server.serve(ctx) }()
	go func() { defer wg.Done(); d.runLoop(ctx) }()

	if d.reconcileEvery > 0 {
		wg.Add(1)
		go func() { defer wg.Done(); d.runReconcile(ctx) }()
	}

	digestEnabled := d.cfg.DigestEnabled || (d.berm != nil && d.berm.Globals.StaleDigest)
	if digestEnabled {
		wg.Add(1)
		go func() { defer wg.Done(); d.runDigest(ctx) }()
	}

	<-ctx.Done()
	d.log.Info("berm daemon shutting down")
	d.server.close()
	d.tracker.stop()
	wg.Wait()
	return nil
}

// EffectiveDefaultDelivery resolves BERM_DEFAULT_DELIVERY: the explicit global
// if set, else the per-runtime default (Docker client, Podman hook), else the
// berm.yml defaults block. It is exported so cmd/berm and the validate/status
// chunks resolve the mechanism the same way the daemon does.
func EffectiveDefaultDelivery(cfg *config.Config) delivery.Mechanism {
	if cfg != nil && cfg.Globals.DefaultDelivery != "" {
		return delivery.Mechanism(cfg.Globals.DefaultDelivery)
	}
	if cfg != nil && cfg.Globals.Runtime == "podman" {
		return delivery.MechHook
	}
	if cfg != nil && cfg.Globals.Runtime == "docker" {
		return delivery.MechClient
	}
	// No runtime hint: fall back to the berm.yml defaults block, else client
	// (the Docker primary), matching the grammar's per-runtime default.
	if cfg != nil && cfg.Defaults.Delivery != "" {
		return delivery.Mechanism(cfg.Defaults.Delivery)
	}
	return delivery.MechClient
}

// recordInjection records a completed injection in the ledger from its manifest,
// clears any sticky error the container had (it now injected cleanly), and logs
// the injection by name. It never touches a secret value: the manifest holds
// hashes and names only.
func (d *Daemon) recordInjection(m *delivery.Manifest) {
	if err := d.ledger.RecordManifest(m, d.now()); err != nil {
		d.log.Error("record injection in ledger failed", "container", m.Container, "err", err.Error())
	}
	d.sticky.clear(m.Container)
	d.log.Info("injected", "container", m.Container, "service", m.Service, "mechanism", m.Mechanism)
}

// alertValidation routes a classified validation failure to the sink and, when
// it is sticky, records it so the scheduled digest keeps it visible until fixed.
// A classified label.Error is value-free by construction, so its message and
// fields are safe to alert. An unclassified error (a backend or runtime failure)
// is alerted with a generic body and no raw error text, since a wrapped error
// chain is not guaranteed value-free the way a label.Error is; the raw error is
// logged to the operator-facing logger only (which the security tests still
// grep for no value). It returns a short, scrubbed reason safe to send back to
// the client over the wire.
func (d *Daemon) alertValidation(ctx context.Context, containerID, service string, err error) string {
	le, ok := label.AsError(err)
	if ok {
		fields := map[string]string{
			"container": containerID,
			"service":   service,
			"class":     le.Class.String(),
		}
		for k, v := range le.Fields {
			fields[k] = v
		}
		d.log.Warn("validation error", "container", containerID, "class", le.Class.String(), "reason", le.Message)
		if d.sink != nil {
			_ = d.sink.Alert(ctx, validationLevel(le), "berm validation error", le.Message, fields)
		}
		if le.Sticky() {
			d.sticky.add(containerID, service, le)
		}
		return le.Message
	}

	// Unclassified: a backend, runtime, or delivery failure. Do not put the raw
	// error chain on the wire or in the sink body; log it for the operator only.
	d.log.Error("injection failed", "container", containerID, "err", err.Error())
	if d.sink != nil {
		_ = d.sink.Alert(ctx, beacon.LevelError, "berm injection failed",
			"a berm injection failed for a container: see the daemon log",
			map[string]string{"container": containerID, "service": service})
	}
	return "internal error"
}

// validationLevel maps a validation class to an alert severity: the sticky
// secrets-affecting classes are errors, the rest warnings.
func validationLevel(le *label.Error) beacon.Level {
	if le.Sticky() {
		return beacon.LevelError
	}
	return beacon.LevelWarning
}

// --- sticky-error store ---

// stickyError is one secrets-affecting validation failure held until the
// container next injects cleanly (or is destroyed). It carries names and a class
// only, never a value.
type stickyError struct {
	Container string
	Service   string
	Class     string
	Message   string
	Since     time.Time
}

// stickyStore holds the sticky validation errors the digest reports. It keys by
// container so a container has at most one standing sticky error (the latest),
// which clears when the container injects cleanly or is destroyed. It is safe
// for concurrent use.
type stickyStore struct {
	mu     sync.Mutex
	byCont map[string]stickyError
}

func newStickyStore() *stickyStore {
	return &stickyStore{byCont: map[string]stickyError{}}
}

func (s *stickyStore) add(containerID, service string, le *label.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byCont[containerID]; !ok {
		s.byCont[containerID] = stickyError{
			Container: containerID, Service: service,
			Class: le.Class.String(), Message: le.Message, Since: time.Now().UTC(),
		}
		return
	}
	// Keep the original Since, refresh the class and message to the latest.
	e := s.byCont[containerID]
	e.Service = service
	e.Class = le.Class.String()
	e.Message = le.Message
	s.byCont[containerID] = e
}

func (s *stickyStore) clear(containerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byCont, containerID)
}

func (s *stickyStore) list() []stickyError {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]stickyError, 0, len(s.byCont))
	for _, e := range s.byCont {
		out = append(out, e)
	}
	return out
}

// --- keyed per-container mutex (in-flight locks) ---

// keyedMutex serializes work per container id, so two lifecycle events for the
// same container (a rapid restart) never drive two concurrent volume applies.
// It is the in-flight lock the architecture names, held only for the duration of
// one apply.
type keyedMutex struct {
	mu   sync.Mutex
	held map[string]*sync.Mutex
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{held: map[string]*sync.Mutex{}}
}

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	m, ok := k.held[key]
	if !ok {
		m = &sync.Mutex{}
		k.held[key] = m
	}
	k.mu.Unlock()
	m.Lock()
	return m.Unlock
}
