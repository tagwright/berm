// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"fmt"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/berm/internal/config"
)

// DefaultDockerSocket and DefaultPodmanSocket are the conventional runtime
// socket paths berm falls back to when BERM_SOCKET is unset. The core runtime
// adapter builds its Engine API host as "unix://" + socket, so it needs a real
// path here: an empty socket would produce the unparseable host "unix://" and
// the daemon would authenticate no one and watch nothing. These are the paths
// the shipped deploy examples mount, which set no BERM_SOCKET.
const (
	DefaultDockerSocket = "/var/run/docker.sock"
	DefaultPodmanSocket = "/run/podman/podman.sock"
)

// SelectRuntime builds the container runtime named by BERM_RUNTIME (loaded into
// config.Globals.Runtime), talking to BERM_SOCKET when set. "docker" (the
// default when unset) builds the Docker adapter, "podman" the Podman adapter.
// An empty BERM_SOCKET falls back to the runtime's conventional socket path
// (DefaultDockerSocket or DefaultPodmanSocket) rather than an empty one, since
// the core adapter cannot build a client from an empty socket. It is exported so
// cmd/berm and the status/stale/validate CLI chunks select the runtime the same
// way the daemon does.
func SelectRuntime(cfg *config.Config) (runtime.Runtime, error) {
	name := ""
	socket := ""
	if cfg != nil {
		name = cfg.Globals.Runtime
		socket = cfg.Globals.Socket
	}
	switch name {
	case "", "docker":
		return runtime.NewDocker(socketOrDefault(name, socket)), nil
	case "podman":
		return runtime.NewPodman(socketOrDefault(name, socket)), nil
	default:
		return nil, fmt.Errorf("daemon: unknown BERM_RUNTIME %q, want docker or podman", name)
	}
}

// socketOrDefault returns socket, or the runtime's conventional socket path when
// socket is empty. An empty socket must never reach the core adapter: it would
// build the unparseable Engine API host "unix://" and the daemon would connect
// to nothing, authenticate no caller, and watch no container. Podman uses its
// own conventional path; everything else uses the Docker default.
func socketOrDefault(runtimeName, socket string) string {
	if socket != "" {
		return socket
	}
	if runtimeName == "podman" {
		return DefaultPodmanSocket
	}
	return DefaultDockerSocket
}
