// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package hookd is the daemon side of hook-mode delivery: it turns a hook
// request (an OCI container id plus that container's OCI annotations, presented
// by the trusted pre-start hook) into that container's file bundle. It is the
// counterpart to the client-fetch handler, and the daemon's socket loop wires it
// in the same way.
//
// Trust model. Unlike the client path there is no SO_PEERCRED here: the hook is
// a trusted, privileged host-side injector with no peer container identity of
// its own. Crucially, the daemon does NOT inspect the container over the runtime
// API to learn its labels: the OCI pre-start hook fires while the runtime holds
// the container-creation lock, so a daemon Inspect of that same container would
// deadlock against the create the hook is blocking (verified live against Podman
// in the nested-podman integration phase). Instead the hook presents the
// container's own OCI annotations (the berm.* config the operator set, which the
// runtime handed the hook in the OCI state), and this handler resolves from
// them. It still VALIDATES rather than blindly delivers: it derives the berm
// service identity the same way the peer-auth path does, resolves the presented
// config against berm.yml (source existence, ref shape, and the owner-plus-grant
// scoping), and refuses a container that is not berm-enabled or whose resolved
// mechanism is not hook. The trust boundary is the same as the rest of berm's
// hook design: a privileged host component presenting a container's own config.
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
// container actually declared. The daemon maps this to a clean skip rather than a
// container-start failure.
var ErrNotHookMode = errors.New("hookd: container did not select hook-mode delivery")

// composeServiceKeys are the annotation keys a compose/pod tool may set to name
// the service, in preference order. They mirror the identity the peer-auth path
// reads from the runtime's normalized compose service; in hook mode the hook has
// no container name to fall back on, so a hook-mode container is identified by a
// berm.name annotation or one of these compose-service annotations.
var composeServiceKeys = []string{
	"com.docker.compose.service",
	"io.podman.compose.service",
}

// Handler builds file bundles for hook requests. It holds the loaded berm.yml,
// the delivery opener over the backend, and the effective default delivery the
// daemon computed per runtime. It is safe for concurrent use if its dependencies
// are. It holds no runtime: the hook path never inspects the container (that
// would deadlock against the create the hook blocks).
type Handler struct {
	cfg             *config.Config
	opener          delivery.Opener
	defaultDelivery delivery.Mechanism
}

// NewHandler builds a hook handler. The daemon constructs one at start and calls
// Handle per hook request.
func NewHandler(cfg *config.Config, opener delivery.Opener, defaultDelivery delivery.Mechanism) *Handler {
	return &Handler{cfg: cfg, opener: opener, defaultDelivery: defaultDelivery}
}

// Handle resolves the container named by containerID, using the annotations the
// hook presented (the container's berm.* config), and returns its file bundle or
// a classified error. The returned bundle holds secret bytes in locked memory;
// the caller (the daemon loop) MUST Destroy it after serializing it onto the
// connection. now is the manifest timestamp clock.
//
// The pipeline is derive identity, resolve, refuse env, build bundle. There is no
// runtime inspect: the presented annotations are the container's own config. Every
// error path returns before any secret is produced except the final build, which
// Destroys its partial bundle itself on error.
func (h *Handler) Handle(ctx context.Context, containerID string, annotations map[string]string, now time.Time) (*wire.Bundle, error) {
	// Reconstruct just enough of the container's identity from the presented
	// annotations to derive the berm service name the resolver scopes against, the
	// same derivation the peer-auth path uses on an inspected container.
	c := runtime.Container{
		ID:      containerID,
		Labels:  annotations,
		Service: composeService(annotations),
	}
	svc, err := peerauth.ServiceName(c)
	if err != nil {
		return nil, fmt.Errorf("hookd: identity for %s: %w", containerID, err)
	}

	plan, err := resolve.Resolve(resolve.Input{
		Labels:          annotations,
		ContainerID:     containerID,
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

	// BuildBundle re-checks scope and the env gate. Passing the plan's own service
	// as the caller makes the scope check a tautology here: the hook is trusted,
	// and the identity was derived from the container's own presented config.
	bundle, err := delivery.BuildBundle(ctx, dplan.Service, dplan, h.opener, now)
	if err != nil {
		return nil, fmt.Errorf("hookd: build bundle for %s: %w", containerID, err)
	}
	return bundle, nil
}

// composeService returns the compose/pod service name from the presented
// annotations, in preference order, or "" if none is set. It lets a hook-mode
// container be identified by its compose service when it sets no berm.name.
func composeService(annotations map[string]string) string {
	for _, k := range composeServiceKeys {
		if v := annotations[k]; v != "" {
			return v
		}
	}
	return ""
}
