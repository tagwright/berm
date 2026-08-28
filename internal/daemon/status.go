// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package daemon

import (
	"context"
	"sort"
	"time"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/label"
	"github.com/tagwright/berm/internal/peerauth"
	"github.com/tagwright/berm/internal/resolve"
)

// ContainerStatus is one berm-enabled container's injection state, the row
// `berm status` (a later chunk) prints. It names the container, its resolved
// mechanism, whether env exposure is in play, whether the ledger has an
// injection recorded and when, which of its sources have drifted since, and any
// standing validation error. It carries no secret value.
type ContainerStatus struct {
	// Container is the container id.
	Container string

	// Service is the resolved service identity.
	Service string

	// Mechanism is the resolved delivery mechanism, empty when the container
	// failed to resolve.
	Mechanism string

	// EnvExposure is set when the container delivers env, which berm status
	// surfaces as the one-time honesty warning: env-delivered secrets are
	// readable via /proc/<pid>/environ inside the container and by host root.
	EnvExposure bool

	// Injected is true when the ledger records an injection for this container.
	Injected bool

	// LastInjected is the timestamp of the recorded injection, zero when none.
	LastInjected time.Time

	// DriftedSources are the sources that changed since the recorded injection,
	// so the operator knows a recreate is pending.
	DriftedSources []string

	// ErrorClass is the class token of a standing validation error, empty when
	// the container resolves cleanly.
	ErrorClass string

	// ErrorMessage is the value-free reason for a standing validation error.
	ErrorMessage string

	// Sticky is true when a standing validation error is secrets-affecting and
	// held in the digest until fixed.
	Sticky bool
}

// Status reports the injection state of every berm-enabled container. It lists
// the runtime's containers, resolves each against berm.yml the same way the
// daemon does, and folds in the recorded injection and current drift from the
// ledger. It is a standalone library query: `berm status` can call it from a
// fresh process with a runtime, the loaded config, a hash source over the
// backend, and the ledger loaded from disk. It never decrypts and never surfaces
// a value.
func Status(ctx context.Context, rt runtime.Runtime, cfg *config.Config, hs HashSource, ledger *Ledger) ([]ContainerStatus, error) {
	containers, err := rt.List(ctx)
	if err != nil {
		return nil, err
	}

	drift, err := ledger.Drift(hs)
	if err != nil {
		return nil, err
	}
	driftByContainer := map[string][]string{}
	for _, dr := range drift {
		driftByContainer[dr.Container] = append(driftByContainer[dr.Container], dr.Source)
	}

	defDeliv := EffectiveDefaultDelivery(cfg)

	var out []ContainerStatus
	for _, c := range containers {
		svc, serr := peerauth.ServiceName(c)
		if serr != nil {
			svc = ""
		}

		plan, rerr := resolve.Resolve(resolve.Input{
			Labels:          c.Labels,
			ContainerID:     c.ID,
			Service:         svc,
			Config:          cfg,
			DefaultDelivery: defDeliv,
		})
		if plan == nil && rerr == nil {
			continue // not berm-enabled
		}

		st := ContainerStatus{Container: c.ID, Service: svc}
		if rec, ok := ledger.Record(c.ID); ok {
			st.Injected = true
			st.LastInjected = rec.UpdatedAt
			if svc == "" {
				st.Service = rec.Service
			}
		}
		if ds := driftByContainer[c.ID]; len(ds) > 0 {
			sort.Strings(ds)
			st.DriftedSources = ds
		}

		if rerr != nil {
			if le, ok := label.AsError(rerr); ok {
				st.ErrorClass = le.Class.String()
				st.ErrorMessage = le.Message
				st.Sticky = le.Sticky()
			} else {
				st.ErrorClass = "error"
				st.ErrorMessage = "resolve failed: see the daemon log"
			}
			out = append(out, st)
			continue
		}

		st.Mechanism = string(plan.Mechanism)
		st.EnvExposure = plan.EnvExposure
		out = append(out, st)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].Container < out[j].Container
	})
	return out, nil
}
