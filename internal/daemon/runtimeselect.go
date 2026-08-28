// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package daemon

import (
	"fmt"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/config"
)

// SelectRuntime builds the container runtime named by BERM_RUNTIME (loaded into
// config.Globals.Runtime), talking to BERM_SOCKET when set. "docker" (the
// default when unset) builds the Docker adapter, "podman" the Podman adapter.
// An empty socket lets the adapter use its conventional default socket. It is
// exported so cmd/berm and the status/stale/validate CLI chunks select the
// runtime the same way the daemon does.
func SelectRuntime(cfg *config.Config) (runtime.Runtime, error) {
	name := ""
	socket := ""
	if cfg != nil {
		name = cfg.Globals.Runtime
		socket = cfg.Globals.Socket
	}
	switch name {
	case "", "docker":
		return runtime.NewDocker(socket), nil
	case "podman":
		return runtime.NewPodman(socket), nil
	default:
		return nil, fmt.Errorf("daemon: unknown BERM_RUNTIME %q, want docker or podman", name)
	}
}
