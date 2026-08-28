// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package resolve

import "github.com/tagwright/berm/internal/delivery"

// ToDelivery translates a resolved Plan into the delivery layer's execution
// vocabulary. resolve is the policy layer (it validates labels against berm.yml
// and scopes to the caller); delivery is the execution layer (it decrypts and
// lands the bytes). This one adapter is the seam between them, which is why the
// delivery package never imports resolve and there is no import cycle: the
// dependency runs one way, resolve -> delivery, the same direction resolve
// already depends on delivery for the Mechanism enum.
//
// The translation is a pure field copy. It carries no secret value, because
// neither Plan holds one: both name targets only.
func (p *Plan) ToDelivery() delivery.Plan {
	dp := delivery.Plan{
		Container:   p.Container,
		Service:     p.Service,
		Mechanism:   p.Mechanism,
		EnvExposure: p.EnvExposure,
	}
	for _, eb := range p.Env {
		dp.Env = append(dp.Env, delivery.EnvTarget{
			Var:    eb.Var,
			Source: eb.Source,
			Key:    eb.Key,
			All:    eb.All,
		})
	}
	for _, fb := range p.Files {
		dp.Files = append(dp.Files, delivery.FileTarget{
			Name:       fb.Name,
			Source:     fb.Source,
			Format:     fb.Format,
			Whole:      fb.Whole,
			Key:        fb.Key,
			Path:       fb.Path,
			Owner:      fb.Owner,
			Mode:       fb.Mode,
			PointerVar: fb.PointerVar,
		})
	}
	for _, rb := range p.Renders {
		dp.Renders = append(dp.Renders, delivery.RenderTarget{
			Kind:   delivery.RenderKind(rb.Kind),
			Source: rb.Source,
			Path:   rb.Path,
			Owner:  rb.Owner,
			Mode:   rb.Mode,
		})
	}
	return dp
}
