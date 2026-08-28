// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package delivery

import "context"

// Volume is the fallback mechanism for both runtimes with no image change. It
// populates a tmpfs-backed named volume (not a bare tmpfs mount, which is not
// shareable between containers) and a waiter service uses the atomic
// appearance of the delivered manifest as its ready signal, closing the
// container-start race. Files only: like the hook, it cannot control the
// process environment, so a plan carrying env deliveries is rejected with
// ErrEnvUnsupported.
//
// Stubbed until the delivery chunk.
type Volume struct{}

// NewVolume builds the tmpfs-volume delivery.
func NewVolume() *Volume { return &Volume{} }

// Mechanism satisfies Delivery.
func (v *Volume) Mechanism() Mechanism { return MechVolume }

// SupportsEnv satisfies Delivery. The volume mechanism cannot set env.
func (v *Volume) SupportsEnv() bool { return false }

// Deliver satisfies Delivery. Stubbed. A plan with env deliveries must be
// rejected with ErrEnvUnsupported here once wired.
func (v *Volume) Deliver(_ context.Context, plan Plan) error {
	if len(plan.Env) > 0 {
		return ErrEnvUnsupported
	}
	return ErrNotImplemented
}

var _ Delivery = (*Volume)(nil)
