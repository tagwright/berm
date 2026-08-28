// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package daemon

import (
	"context"
	"path/filepath"
	"time"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/delivery"
	"github.com/tagwright/berm/internal/peerauth"
	"github.com/tagwright/berm/internal/resolve"
)

// runLoop is the event-driven control loop. It watches the runtime for
// lifecycle events and acts on each: a started volume-mode container is pushed
// its secrets (the daemon writes into the shared tmpfs volume, whose manifest is
// the ready signal); a started client-mode container is registered for the
// client-fetch timeout; a stopped or destroyed container has its in-flight state
// cleared. Client- and hook-mode containers are otherwise pull-driven (their
// wrapper or the OCI hook fetches), so the loop never pushes to them.
//
// The loop reconnects with backoff if the watch stream ends before ctx is
// cancelled, so a runtime socket blip does not silently stop the daemon
// reacting to new containers.
func (d *Daemon) runLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		d.watchOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// watchOnce runs one Watch subscription to completion (its end, or ctx cancel).
func (d *Daemon) watchOnce(ctx context.Context) {
	events, errs := d.rt.Watch(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-errs:
			if !ok {
				return
			}
			if err != nil {
				d.log.Warn("runtime watch error", "err", err.Error())
			}
		case ev, ok := <-events:
			if !ok {
				return
			}
			d.handleEvent(ctx, ev)
		}
	}
}

// handleEvent dispatches one lifecycle event.
func (d *Daemon) handleEvent(ctx context.Context, ev runtime.Event) {
	switch ev.Type {
	case runtime.EventStart:
		d.handleStart(ctx, ev.ID)
	case runtime.EventStop, runtime.EventDie, runtime.EventDestroy:
		d.tracker.cancel(ev.ID)
		if ev.Type == runtime.EventDestroy {
			if err := d.ledger.Forget(ev.ID); err != nil {
				d.log.Error("forget destroyed container in ledger failed", "container", ev.ID, "err", err.Error())
			}
			d.sticky.clear(ev.ID)
		}
	}
}

// handleStart resolves a started container and acts by its mechanism. A
// non-berm container resolves to a nil plan and is ignored. A validation failure
// is skip-and-alert. A volume-mode container is pushed its secrets; a
// client-mode container is registered for the fetch timeout; a hook-mode
// container is left for the OCI hook to fetch.
func (d *Daemon) handleStart(ctx context.Context, containerID string) {
	c, err := d.rt.Inspect(ctx, containerID)
	if err != nil {
		d.log.Warn("inspect started container failed", "container", containerID, "err", err.Error())
		return
	}

	svc, err := peerauth.ServiceName(c)
	if err != nil {
		// A container whose identity is ambiguous (conflicting berm.name across
		// prefixes) is a config error, not a secret: alert without a value.
		d.log.Warn("service identity failed", "container", containerID, "err", err.Error())
		return
	}

	plan, rerr := resolve.Resolve(resolve.Input{
		Labels:          c.Labels,
		ContainerID:     c.ID,
		Service:         svc,
		Config:          d.berm,
		DefaultDelivery: d.defDeliv,
	})
	if rerr != nil {
		d.alertValidation(ctx, c.ID, svc, rerr)
		return
	}
	if plan == nil {
		return // not berm-enabled
	}

	switch plan.Mechanism {
	case delivery.MechVolume:
		d.pushVolume(ctx, plan, c)
	case delivery.MechClient:
		d.tracker.expect(c.ID, svc)
	case delivery.MechHook:
		// Pull-driven: the OCI pre-start hook fetches. The loop does not push.
	}
}

// pushVolume writes a volume-mode plan into the container's shared tmpfs named
// volume and records the injection. The daemon-side mount path for the volume is
// <VolumeMountRoot>/<volume name>, where the volume name is berm.volume or the
// default berm-<service>. The write goes through delivery.ApplyVolume, which
// writes the manifest last and atomically as the waiter's ready signal, and
// which refuses a non-tmpfs target. The per-container in-flight lock serializes
// a rapid restart's two starts.
func (d *Daemon) pushVolume(ctx context.Context, plan *resolve.Plan, c runtime.Container) {
	unlock := d.locks.lock(c.ID)
	defer unlock()

	volName := volumeName(c, plan.Service)
	mountPath := filepath.Join(d.volRoot, volName)
	dplan := plan.ToDelivery()

	now := d.now()
	if err := delivery.ApplyVolume(ctx, dplan, d.opener, mountPath, now); err != nil {
		d.alertValidation(ctx, c.ID, plan.Service, err)
		return
	}

	// Record from a freshly built manifest (hashes the ciphertext, no decrypt),
	// the same manifest ApplyVolume wrote into the volume.
	m, err := delivery.BuildManifest(dplan, d.opener, now)
	if err != nil {
		d.log.Error("build manifest for ledger failed", "container", c.ID, "err", err.Error())
		return
	}
	d.recordInjection(m)
}

// volumeName resolves the tmpfs mount name for volume mode: the berm.volume
// label under either recognized prefix, else the default berm-<service>.
func volumeName(c runtime.Container, service string) string {
	if v := c.Labels["berm.volume"]; v != "" {
		return v
	}
	if v := c.Labels["tagwright.secret.volume"]; v != "" {
		return v
	}
	return "berm-" + service
}
