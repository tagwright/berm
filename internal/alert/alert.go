// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package alert is berm's diagnostics seam over courier. The label grammar is
// skip-and-alert: a validation failure on one container (an unknown suffix, an
// ungranted reference, a missing source, an env label without its
// acknowledgment) skips that one container and alerts, never breaking
// injection for the rest of the fleet. Secrets-affecting errors are meant to
// stay sticky in the beacon digest until fixed. This package is where that
// alerting lands.
//
// A Sink never carries a secret value. It reports names, reasons, and
// severities only, the same no-log-a-secret discipline the whole tool holds.
package alert

import (
	"context"

	"github.com/tagwright/courier"
)

// Sink receives berm diagnostics. It is satisfied by a beacon-backed
// implementation and by a no-op for tests. The message and fields must never
// contain a secret value.
type Sink interface {
	// Alert reports one diagnostic at a severity, with structured
	// name/value fields (a container name, a source name, a reason), none of
	// which is ever a secret value.
	Alert(ctx context.Context, level courier.Level, title, body string, fields map[string]string) error
}

// BeaconSink routes berm diagnostics through beacon, the suite's alerting and
// telemetry library. Diagnostics are delivered through beacon and Gatus
// telemetry is available alongside.
type BeaconSink struct {
	b *courier.Beacon
}

// NewBeaconSink wraps a configured *courier.Beacon as a Sink.
func NewBeaconSink(b *courier.Beacon) *BeaconSink {
	return &BeaconSink{b: b}
}

// Alert satisfies Sink by sending a courier.Notification.
func (s *BeaconSink) Alert(ctx context.Context, level courier.Level, title, body string, fields map[string]string) error {
	return s.b.Notify(ctx, courier.Notification{
		Title:  title,
		Body:   body,
		Level:  level,
		Fields: fields,
	})
}

var _ Sink = (*BeaconSink)(nil)
