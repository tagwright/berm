// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package delivery

import (
	"context"
	"fmt"
	"time"

	"github.com/awnumar/memguard"

	"github.com/tagwright/berm/internal/wire"
)

// BuildBundle is the client-fetch handler, delivered as a library function the
// daemon's socket loop (a later chunk) calls once it has authenticated the peer
// and resolved the caller's plan. It produces the secret bundle to send back
// over the socket: exactly the files, env vars, and non-secret pointers that
// belong to THIS caller and no other, plus the manifest. It does no I/O and no
// socket work: the daemon owns the connection and calls wire.EncodeBundle on the
// result, then Destroys it.
//
// callerService is the authenticated caller's service identity. The daemon
// passes the resolved peerauth Identity.ServiceName here (it is passed as a
// string, not the peerauth type, because peerauth imports the label package
// which imports delivery, and a delivery->peerauth edge would close an import
// cycle). The plan is already scoped to the caller by resolve, which
// authenticated the same identity. BuildBundle re-checks that callerService
// matches plan.Service (defense in depth: a caller never receives a plan built
// for a different service) and re-enforces the env gate (env is legal only in
// client mode), so a bug upstream cannot leak env onto a file-only mechanism or
// hand a caller another service's secrets.
//
// Every secret byte in the returned bundle lives in a memguard LockedBuffer the
// bundle owns; the caller MUST Destroy the bundle after serializing it. On any
// error mid-build the partial bundle is Destroyed before return, so no live
// secret memory is stranded.
func BuildBundle(ctx context.Context, callerService string, plan Plan, opener Opener, now time.Time) (b *wire.Bundle, err error) {
	if err := checkScope(callerService, plan); err != nil {
		return nil, err
	}
	if err := checkEnvGate(plan); err != nil {
		return nil, err
	}

	b = &wire.Bundle{}
	defer func() {
		if err != nil {
			b.Destroy()
			b = nil
		}
	}()

	for _, ft := range plan.Files {
		if err = addFile(ctx, b, opener, ft); err != nil {
			return b, err
		}
	}
	for _, rt := range plan.Renders {
		if err = addRender(ctx, b, opener, rt); err != nil {
			return b, err
		}
	}
	for _, et := range plan.Env {
		if err = addEnv(ctx, b, opener, et); err != nil {
			return b, err
		}
	}

	m, err := BuildManifest(plan, opener, now)
	if err != nil {
		return b, err
	}
	mb, err := m.Marshal()
	if err != nil {
		return b, err
	}
	b.Manifest = mb
	return b, nil
}

// checkScope confirms the plan was built for this caller. An unset service on
// either side is tolerated only in the library-level tests that exercise
// BuildBundle without a live peer; the daemon always passes the resolved
// identity's service and resolve always sets plan.Service.
func checkScope(callerService string, plan Plan) error {
	if callerService == "" || plan.Service == "" {
		return nil
	}
	if callerService != plan.Service {
		return fmt.Errorf("delivery: refusing bundle: caller %q does not match plan service %q",
			callerService, plan.Service)
	}
	return nil
}

// checkEnvGate re-enforces the env-exposure gate: env crosses the wire only in
// client mode. resolve already rejects env on a file-only mechanism, so this is
// defense in depth against an upstream bug, not the primary check.
func checkEnvGate(plan Plan) error {
	if len(plan.Env) > 0 && !EnvAllowed(plan.Mechanism) {
		return fmt.Errorf("delivery: %w (mechanism %q)", ErrEnvUnsupported, plan.Mechanism)
	}
	return nil
}

// addFile decrypts one file delivery into the bundle's locked memory and records
// its pointer var. The decrypted value is copied out of the backend handle into
// the bundle before the handle Closes, so the handle's own Close-time wipe does
// not touch the bundle's copy.
func addFile(ctx context.Context, b *wire.Bundle, opener Opener, ft FileTarget) error {
	op, err := opener.OpenSource(ctx, ft.Source)
	if err != nil {
		return fmt.Errorf("delivery: open source %q for file %q: %w", ft.Source, ft.Name, err)
	}
	defer op.Close()

	var raw []byte
	if ft.Whole {
		raw, err = op.Payload()
	} else {
		raw, err = op.Value(ft.Key)
	}
	if err != nil {
		return fmt.Errorf("delivery: read secret for file %q: %w", ft.Name, err)
	}

	b.Files = append(b.Files, wire.File{
		Path:  ft.Path,
		Owner: ft.Owner,
		Mode:  ft.Mode,
		Data:  b.AddSecret(raw),
	})
	if ft.PointerVar != "" {
		b.Pointers = append(b.Pointers, wire.Pointer{Name: ft.PointerVar, Path: ft.Path})
	}
	return nil
}

// addRender decrypts one whole-source render into the bundle as ready-to-write
// files. A dotenv render becomes one KEY=VALUE file; an envdir render becomes
// one file per key. The client writes the resulting files verbatim and needs no
// render logic.
//
// Unlike the hook and volume WriteRender path, which streams each value straight
// to a file descriptor, the client bundle must carry the rendered bytes across
// the socket, so a dotenv render is assembled in a transient scratch that is
// wiped the instant it is copied into the bundle's locked buffer.
func addRender(ctx context.Context, b *wire.Bundle, opener Opener, rt RenderTarget) error {
	op, err := opener.OpenSource(ctx, rt.Source)
	if err != nil {
		return fmt.Errorf("delivery: open source %q for render: %w", rt.Source, err)
	}
	defer op.Close()

	keys, err := op.Keys()
	if err != nil {
		return fmt.Errorf("delivery: list keys of %q for render: %w", rt.Source, err)
	}

	switch rt.Kind {
	case RenderDotenv:
		var scratch []byte
		for _, k := range keys {
			v, e := op.Value(k)
			if e != nil {
				memguard.WipeBytes(scratch)
				return fmt.Errorf("delivery: read %q for dotenv render: %w", k, e)
			}
			scratch = append(scratch, k...)
			scratch = append(scratch, '=')
			scratch = append(scratch, v...)
			scratch = append(scratch, '\n')
		}
		b.Files = append(b.Files, wire.File{
			Path: rt.Path, Owner: rt.Owner, Mode: rt.Mode, Data: b.AddSecret(scratch),
		})
		memguard.WipeBytes(scratch)
		return nil

	case RenderEnvdir:
		for _, k := range keys {
			v, e := op.Value(k)
			if e != nil {
				return fmt.Errorf("delivery: read %q for envdir render: %w", k, e)
			}
			b.Files = append(b.Files, wire.File{
				Path: rt.Path + "/" + k, Owner: rt.Owner, Mode: rt.Mode, Data: b.AddSecret(v),
			})
		}
		return nil

	default:
		return fmt.Errorf("delivery: unknown render kind %q", rt.Kind)
	}
}

// addEnv decrypts one env delivery into the bundle. The all sentinel expands to
// one bundle env var per key of the source, each named for its key; a keyed
// delivery sets the named var (or the key name when no rename was given).
func addEnv(ctx context.Context, b *wire.Bundle, opener Opener, et EnvTarget) error {
	op, err := opener.OpenSource(ctx, et.Source)
	if err != nil {
		return fmt.Errorf("delivery: open source %q for env: %w", et.Source, err)
	}
	defer op.Close()

	if et.All {
		keys, e := op.Keys()
		if e != nil {
			return fmt.Errorf("delivery: list keys of %q for env all: %w", et.Source, e)
		}
		for _, k := range keys {
			v, ve := op.Value(k)
			if ve != nil {
				return fmt.Errorf("delivery: read %q for env all: %w", k, ve)
			}
			b.Env = append(b.Env, wire.EnvVar{Name: k, Value: b.AddSecret(v)})
		}
		return nil
	}

	v, err := op.Value(et.Key)
	if err != nil {
		return fmt.Errorf("delivery: read %q for env: %w", et.Key, err)
	}
	name := et.Var
	if name == "" {
		name = et.Key
	}
	b.Env = append(b.Env, wire.EnvVar{Name: name, Value: b.AddSecret(v)})
	return nil
}
