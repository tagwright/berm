// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package daemon

import "testing"

// TestSocketOrDefaultNeverEmpty pins the integration finding that an unset
// BERM_SOCKET must fall back to the runtime's conventional socket, never an
// empty string. The core adapter builds its host as "unix://" + socket, so an
// empty socket yields the unparseable host "unix://": the daemon then connects
// to nothing, authenticates no caller (every fetch is refused "unauthenticated"),
// and watches no container. Found live in the chunk-9a integration harness,
// where the shipped deploy sets no BERM_SOCKET.
func TestSocketOrDefaultNeverEmpty(t *testing.T) {
	cases := []struct {
		name    string
		runtime string
		socket  string
		want    string
	}{
		{"docker empty -> default", "docker", "", DefaultDockerSocket},
		{"unset runtime empty -> docker default", "", "", DefaultDockerSocket},
		{"podman empty -> podman default", "podman", "", DefaultPodmanSocket},
		{"explicit socket passes through", "docker", "/custom/docker.sock", "/custom/docker.sock"},
		{"explicit podman socket passes through", "podman", "/run/user/1000/podman/podman.sock", "/run/user/1000/podman/podman.sock"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := socketOrDefault(c.runtime, c.socket)
			if got == "" {
				t.Fatalf("socketOrDefault(%q,%q) returned empty: core would build the invalid host \"unix://\"", c.runtime, c.socket)
			}
			if got != c.want {
				t.Fatalf("socketOrDefault(%q,%q) = %q, want %q", c.runtime, c.socket, got, c.want)
			}
		})
	}
}
