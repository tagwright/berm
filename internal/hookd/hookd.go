// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Package hookd is the daemon side of hook-mode delivery: it turns a hook
// request (a bare OCI container id, presented by the trusted pre-start hook)
// into that container's file bundle. It is the counterpart to the client-fetch
// handler, and chunk 6 wires it into the daemon's socket loop the same way.
//
// Trust model. Unlike the client path there is no SO_PEERCRED here: the hook is
// a trusted, privileged host-side injector with no peer container identity of
// its own. It presents a container id, and this handler VALIDATES that id rather
// than trusting it: it inspects the container, derives its berm service identity
// the same way the peer-auth path does, and resolves its labels against
// berm.yml. A container that is not berm-enabled, or whose labels do not
// resolve, is refused. Nothing is delivered on the strength of the id alone.
//
// Files only. Hook mode cannot control the process environment, so env is
// refused. The resolver already refuses env on the hook mechanism, and this
// handler double-checks the resolved plan for env as defense in depth.
package hookd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/delivery"
	"github.com/tagwright/berm/internal/peerauth"
	"github.com/tagwright/berm/internal/resolve"
	"github.com/tagwright/berm/internal/wire"
)

// ErrNotEnabled is returned when a hook request names a container that is not
// berm-enabled. A hook that fired for a non-berm container is a misconfiguration
// (the hook when-conditions should target only berm-labeled containers), and the
// daemon refuses rather than deliver nothing silently.
var ErrNotEnabled = errors.New("hookd: container is not berm-enabled")

// ErrNotHookMode is returned when a hook request names a berm container whose
// resolved delivery mechanism is not hook (it chose client or volume). The hook
// must not inject into it, since that would collide with the mechanism the
// container actually declared. Chunk 6 maps this to a clean skip rather than a
// container-start failure.
var ErrNotHookMode = errors.New("hookd: container did not select hook-mode delivery")

// Handler builds file bundles for hook requests. It holds the runtime (to
// inspect the presented container), the loaded berm.yml, the delivery opener
// over the backend, and the effective default delivery the daemon computed per
// runtime. It is safe for concurrent use if its dependencies are.
type Handler struct {
	rt              runtime.Runtime
	cfg             *config.Config
	opener          delivery.Opener
	defaultDelivery delivery.Mechanism
}

// NewHandler builds a hook handler. Chunk 6 constructs one at daemon start and
// calls Handle per hook request.
func NewHandler(rt runtime.Runtime, cfg *config.Config, opener delivery.Opener, defaultDelivery delivery.Mechanism) *Handler {
	return &Handler{rt: rt, cfg: cfg, opener: opener, defaultDelivery: defaultDelivery}
}

// Handle resolves the container named by containerID and returns its file
// bundle, or a classified error. The returned bundle holds secret bytes in
// locked memory; the caller (the daemon loop) MUST Destroy it after serializing
// it onto the connection. now is the manifest timestamp clock.
//
// The pipeline is inspect, derive identity, resolve, refuse env, build bundle.
// Every error path returns before any secret is produced except the final build,
// which Destroys its partial bundle itself on error.
func (h *Handler) Handle(ctx context.Context, containerID string, now time.Time) (*wire.Bundle, error) {
	c, err := h.rt.Inspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("hookd: inspect %s: %w", containerID, err)
	}

	svc, err := peerauth.ServiceName(c)
	if err != nil {
		return nil, fmt.Errorf("hookd: identity for %s: %w", containerID, err)
	}

	plan, err := resolve.Resolve(resolve.Input{
		Labels:          c.Labels,
		ContainerID:     c.ID,
		Service:         svc,
		Config:          h.cfg,
		DefaultDelivery: h.defaultDelivery,
	})
	if err != nil {
		return nil, fmt.Errorf("hookd: resolve %s: %w", containerID, err)
	}
	if plan == nil {
		return nil, fmt.Errorf("hookd: %w: %s", ErrNotEnabled, containerID)
	}
	if plan.Mechanism != delivery.MechHook {
		return nil, fmt.Errorf("hookd: %w (mechanism %q): %s", ErrNotHookMode, plan.Mechanism, containerID)
	}

	dplan := plan.ToDelivery()
	// Defense in depth: env is impossible in hook mode. The resolver already
	// refuses env on the hook mechanism, so a non-empty Env here would be an
	// upstream bug, not operator input.
	if len(dplan.Env) > 0 {
		return nil, fmt.Errorf("hookd: %w (container %s)", delivery.ErrEnvUnsupported, containerID)
	}

	// BuildBundle re-checks scope and the env gate. Passing the plan's own
	// service as the caller makes the scope check a tautology here: the hook is
	// trusted, and the container was validated by inspection above.
	bundle, err := delivery.BuildBundle(ctx, dplan.Service, dplan, h.opener, now)
	if err != nil {
		return nil, fmt.Errorf("hookd: build bundle for %s: %w", containerID, err)
	}
	return bundle, nil
}
