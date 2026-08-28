// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Package delivery is berm's seam over the three ways a resolved secret
// reaches a container: the one-shot client wrapper, the OCI pre-start hook,
// and the tmpfs-backed volume waiter. All three are built in the first
// campaign. File and tmpfs delivery is the secure default.
//
// The env-exposure gate lives here. Env delivery is the one exposed path, and
// only the client mechanism can perform it, because only the client controls
// the process environment at exec. hook and volume refuse env outright: they
// cannot set env without it landing in inspect, and a silent no-op would be
// worse than an error. EnvAllowed and Delivery.SupportsEnv express that gate
// so the resolver can reject an env delivery on a file-only mechanism as a
// validation error rather than dropping it silently.
package delivery

import (
	"context"
	"errors"

	"github.com/tagwright/berm/internal/backend"
)

// ErrNotImplemented is returned by a mechanism method that is not wired up yet.
var ErrNotImplemented = errors.New("delivery: not implemented")

// ErrEnvUnsupported is returned when a Plan carries env deliveries for a
// mechanism that cannot control the process environment (hook or volume).
var ErrEnvUnsupported = errors.New("delivery: env delivery is refused in hook and volume modes")

// Mechanism is the closed set of delivery mechanisms. It matches the
// berm.delivery label enum. There is no inference: the mechanism is explicit,
// defaulting only from BERM_DEFAULT_DELIVERY.
type Mechanism string

const (
	// MechClient is the one-shot client wrapper in the container entrypoint. It
	// fetches over the peer-authenticated socket and execs the app with the
	// secrets in place. The only mechanism that can deliver env.
	MechClient Mechanism = "client"

	// MechHook is the OCI pre-start hook that writes files into the container's
	// mount namespace before PID 1. Files only.
	MechHook Mechanism = "hook"

	// MechVolume is the tmpfs-backed named volume plus a waiter that closes the
	// container-start race. Files only.
	MechVolume Mechanism = "volume"
)

// Valid reports whether m is a recognized mechanism.
func (m Mechanism) Valid() bool {
	return m == MechClient || m == MechHook || m == MechVolume
}

// EnvAllowed reports whether a mechanism may deliver secrets into the process
// environment. Only the client wrapper can. This is the single source of the
// env-exposure gate: the resolver consults it to reject an env delivery on a
// file-only mechanism.
func EnvAllowed(m Mechanism) bool {
	return m == MechClient
}

// FileTarget is one resolved file delivery: what to read and where the
// plaintext lands, with what ownership. It carries no secret value. The bytes
// are pulled from the backend at delivery time and streamed to Path (hook and
// volume) or serialized into the caller's bundle (client), never held in the
// Plan.
//
// This mirrors resolve.FileBinding. resolve is the policy layer (it validates
// labels against berm.yml and scopes to the caller); delivery is the execution
// layer (it decrypts and lands the bytes). resolve.Plan.ToDelivery is the one
// adapter that translates the resolved bindings into these execution targets,
// which is why delivery need not import resolve and there is no import cycle.
type FileTarget struct {
	// Name is the delivery name from berm.file.<name>.*.
	Name string

	// Source is the resolved source to read from.
	Source string

	// Format is the source's declared format.
	Format backend.SourceFormat

	// Whole is true for a binary whole-payload delivery; when false Key names
	// the dotenv key.
	Whole bool

	// Key is the dotenv key to read. Empty when Whole.
	Key string

	// Path is the absolute, tmpfs-backed destination.
	Path string

	// Owner is uid[:gid], numeric only.
	Owner string

	// Mode is an octal string, e.g. "0400".
	Mode string

	// PointerVar is the non-secret <KEY>_FILE pointer env var to auto-set to
	// Path, or empty. In client mode it becomes a Pointer in the bundle; in
	// file-only modes it is recorded in the manifest for the app to read. Its
	// value is a path, not a secret.
	PointerVar string
}

// EnvTarget is one resolved env delivery: the variable to set and what to read
// for it. It carries no secret value. Legal only on a mechanism where
// EnvAllowed is true.
type EnvTarget struct {
	// Var is the environment variable name to set at exec. Empty when All.
	Var string

	// Source is the resolved source to read from.
	Source string

	// Key is the dotenv key to read. Empty when All.
	Key string

	// All expands to every key of Source, each set as an env var named for its
	// key. Legal only on the caller's own owned default source.
	All bool
}

// RenderKind is which whole-source render shape a RenderTarget is.
type RenderKind string

const (
	// RenderDotenv renders the whole default source as one dotenv file.
	RenderDotenv RenderKind = "dotenv"

	// RenderEnvdir renders the whole default source key-per-file, the s6-overlay
	// container_environment style.
	RenderEnvdir RenderKind = "envdir"
)

// RenderTarget is one resolved whole-source render (berm.dotenv, berm.envdir).
// Both shapes are file-mode and operate on the default source only.
type RenderTarget struct {
	// Kind is dotenv or envdir.
	Kind RenderKind

	// Source is the default source being rendered.
	Source string

	// Path is the absolute target (a file for dotenv, a directory for envdir).
	Path string

	// Owner is uid[:gid], numeric only.
	Owner string

	// Mode is an octal string.
	Mode string
}

// Plan is the resolved set of deliveries for one container, produced by the
// resolver and executed by a Delivery. It names targets only and never holds
// plaintext: a Delivery pulls each value from the backend at execution time
// and streams it to its destination, so the plaintext window stays as narrow
// as the security contract requires.
type Plan struct {
	// Container is the target container ID.
	Container string

	// Service is the resolved service identity the plan was scoped against.
	Service string

	// Mechanism is the delivery mechanism resolved for this container.
	Mechanism Mechanism

	// Files are the file deliveries, the secure default path.
	Files []FileTarget

	// Env are the env deliveries. Non-empty is legal only when
	// EnvAllowed(Mechanism) is true; otherwise the resolver rejects the Plan
	// with ErrEnvUnsupported before it reaches a Delivery.
	Env []EnvTarget

	// Renders are the whole-source renders (berm.dotenv, berm.envdir).
	Renders []RenderTarget

	// EnvExposure is set when the plan delivers any env, so berm status can
	// surface the one-time honesty warning.
	EnvExposure bool
}

// Delivery executes resolved Plans by one mechanism. Implementations live in
// client.go, hook.go, and volume.go.
type Delivery interface {
	// Mechanism reports which mechanism this Delivery implements.
	Mechanism() Mechanism

	// SupportsEnv reports whether this mechanism can deliver env, mirroring
	// EnvAllowed(Mechanism()). It is on the interface so a caller holding only
	// a Delivery can check the gate without switching on the mechanism value.
	SupportsEnv() bool

	// Deliver executes plan for its one container. It must reject a plan whose
	// Env is non-empty when SupportsEnv is false with ErrEnvUnsupported.
	Deliver(ctx context.Context, plan Plan) error
}
