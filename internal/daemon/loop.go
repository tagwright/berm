// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/delivery"
	"github.com/tagwright/berm/internal/peerauth"
	"github.com/tagwright/berm/internal/resolve"
	"github.com/tagwright/berm/internal/wire"
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

// runReconcile periodically populates volume-mode containers whose shared tmpfs
// volume is missing its manifest (the ready signal). It closes a gap the event
// watch alone cannot: the runtime emits no create event through core, so a
// volume-mode container that has been CREATED but whose START is gated cannot be
// populated on a start event, because that start never happens. This is exactly
// the shipped volume deploy topology (a waiter blocks on the manifest, and the
// app depends_on the waiter's clean completion): the app is created up front by
// compose, then waits, and its start is what the waiter blocks on, so without
// this reconcile the manifest never appears and the deploy deadlocks.
//
// The reconcile is idempotent and quiet: it acts on a container only when the
// manifest is absent, so a volume it has already populated is skipped, and it
// resolves labels against berm.yml but does not alert on a validation failure
// here (the start-event path owns alerting), to avoid an alert every interval.
// It populates only volume-mode containers whose named volume the operator
// mounted into the daemon, which is the same precondition start-event delivery
// needs, so it never touches a container it could not already serve.
func (d *Daemon) runReconcile(ctx context.Context) {
	if d.reconcileEvery <= 0 {
		return
	}
	d.reconcileVolumes(ctx)
	t := time.NewTicker(d.reconcileEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reconcileVolumes(ctx)
		}
	}
}

// reconcileVolumes lists every container and populates any volume-mode berm
// container whose shared volume is mounted into the daemon but is missing its
// manifest. It is List-driven (labels and state come back with the listing, so
// no per-container inspect), and it resolves and decrypts only for the volume
// containers that still need populating.
func (d *Daemon) reconcileVolumes(ctx context.Context) {
	containers, err := d.rt.List(ctx)
	if err != nil {
		d.log.Warn("reconcile list failed", "err", err.Error())
		return
	}
	for _, c := range containers {
		svc, err := peerauth.ServiceName(c)
		if err != nil {
			continue
		}
		plan, rerr := resolve.Resolve(resolve.Input{
			Labels:          c.Labels,
			ContainerID:     c.ID,
			Service:         svc,
			Config:          d.berm,
			DefaultDelivery: d.defDeliv,
		})
		// Not berm-enabled, or a validation error: the start-event path handles
		// alerting. Reconcile stays silent so it cannot storm the sink.
		if rerr != nil || plan == nil || plan.Mechanism != delivery.MechVolume {
			continue
		}
		volName := volumeName(c, plan.Service)
		mountPath := filepath.Join(d.volRoot, volName)
		// Only a volume the operator mounted into the daemon can be written.
		if _, err := os.Stat(mountPath); err != nil {
			continue
		}
		// Skip a volume already populated: the manifest is the ready signal, so
		// its presence means this container has been served.
		manifestPath := filepath.Join(mountPath, filepath.Base(wire.DefaultManifestPath))
		if _, err := os.Stat(manifestPath); err == nil {
			continue
		}
		d.log.Info("reconcile: populating a created-but-not-started volume container", "container", c.ID, "service", plan.Service)
		d.pushVolume(ctx, plan, c)
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
