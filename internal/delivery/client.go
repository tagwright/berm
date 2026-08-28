// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package delivery

import "context"

// Client is the one-shot client-wrapper mechanism, the Docker primary. The
// berm-client binary in the container entrypoint fetches over the
// peer-authenticated socket and execs the real process with the secrets in
// place. It is the only mechanism that can deliver env, because it is the only
// one that controls the process environment at exec.
//
// Stubbed until the delivery chunk.
type Client struct{}

// NewClient builds the client-wrapper delivery.
func NewClient() *Client { return &Client{} }

// Mechanism satisfies Delivery.
func (c *Client) Mechanism() Mechanism { return MechClient }

// SupportsEnv satisfies Delivery. The client wrapper is the one env-capable
// mechanism.
func (c *Client) SupportsEnv() bool { return true }

// Deliver satisfies Delivery. Stubbed.
func (c *Client) Deliver(_ context.Context, _ Plan) error {
	return ErrNotImplemented
}

var _ Delivery = (*Client)(nil)
