// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package delivery

import "context"

// Hook is the OCI pre-start hook mechanism, the Podman primary. A precreate
// and createContainer hook writes the secret files into the container's own
// mount namespace before PID 1, so there is no client binary and no start
// race. Files only: the hook cannot control the process environment, so a plan
// carrying env deliveries is rejected with ErrEnvUnsupported.
//
// Stubbed until the delivery chunk.
type Hook struct{}

// NewHook builds the pre-start-hook delivery.
func NewHook() *Hook { return &Hook{} }

// Mechanism satisfies Delivery.
func (h *Hook) Mechanism() Mechanism { return MechHook }

// SupportsEnv satisfies Delivery. The hook cannot set env.
func (h *Hook) SupportsEnv() bool { return false }

// Deliver satisfies Delivery. Stubbed. A plan with env deliveries must be
// rejected with ErrEnvUnsupported here once wired.
func (h *Hook) Deliver(_ context.Context, plan Plan) error {
	if len(plan.Env) > 0 {
		return ErrEnvUnsupported
	}
	return ErrNotImplemented
}

var _ Delivery = (*Hook)(nil)
