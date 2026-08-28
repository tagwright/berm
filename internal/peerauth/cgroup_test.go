// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package peerauth

import (
	"errors"
	"testing"
)

// idA and idB are two distinct, well-formed 64-hex container ids used across
// the fixture cgroup contents.
const (
	idA = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	idB = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestParseCgroupContainerID(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
		wantErr error
	}{
		{
			name:    "docker v2 systemd",
			content: "0::/system.slice/docker-" + idA + ".scope\n",
			want:    idA,
		},
		{
			name:    "docker v2 cgroupfs",
			content: "0::/docker/" + idA + "\n",
			want:    idA,
		},
		{
			name: "docker v1 multi-hierarchy",
			content: "12:pids:/docker/" + idA + "\n" +
				"11:hugetlb:/docker/" + idA + "\n" +
				"6:cpu,cpuacct:/docker/" + idA + "\n" +
				"1:name=systemd:/docker/" + idA + "\n",
			want: idA,
		},
		{
			name:    "podman rootful v2",
			content: "0::/machine.slice/libpod-" + idA + ".scope/container\n",
			want:    idA,
		},
		{
			name: "podman rootless v2 under user.slice",
			content: "0::/user.slice/user-1000.slice/user@1000.service/user.slice/" +
				"libpod-" + idA + ".scope/container\n",
			want: idA,
		},
		{
			name: "podman v1 rootful cgroupfs no scope suffix",
			content: "1:name=systemd:/machine.slice/libpod-" + idA + "\n" +
				"0::/machine.slice/libpod-" + idA + "\n",
			want: idA,
		},
		{
			name:    "cri-containerd systemd",
			content: "0::/kubepods.slice/kubepods-burstable.slice/cri-containerd-" + idA + ".scope\n",
			want:    idA,
		},
		// Fail-closed cases below.
		{
			name:    "empty content",
			content: "",
			wantErr: ErrNoContainerID,
		},
		{
			name:    "cgroup root only (daemon in own cgroupns)",
			content: "0::/\n",
			wantErr: ErrNoContainerID,
		},
		{
			name:    "non-container systemd slice",
			content: "0::/system.slice/sshd.service\n",
			wantErr: ErrNoContainerID,
		},
		{
			name:    "docker prefix but not hex id",
			content: "0::/system.slice/docker-notavalidcontaineridxxxxxxxxxxxxxxxxxxxxxxxxxxx.scope\n",
			wantErr: ErrNoContainerID,
		},
		{
			name:    "too-short hex is not an id",
			content: "0::/docker/abcdef0123456789\n",
			wantErr: ErrNoContainerID,
		},
		{
			name:    "two distinct ids is ambiguous",
			content: "0::/system.slice/docker-" + idA + ".scope\n1:name=systemd:/docker/" + idB + "\n",
			wantErr: ErrAmbiguousContainerID,
		},
		{
			name:    "garbage lines",
			content: "this is not a cgroup file\n\n:::::\n",
			wantErr: ErrNoContainerID,
		},
		{
			name:    "same id repeated across lines is fine",
			content: "0::/system.slice/docker-" + idA + ".scope\n1:name=systemd:/docker/" + idA + "\n",
			want:    idA,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCgroupContainerID(tc.content)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("want error %v, got %v (id %q)", tc.wantErr, err, got)
				}
				if got != "" {
					t.Fatalf("fail-closed must return empty id, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("want id %q, got %q", tc.want, got)
			}
		})
	}
}

func TestIsHex64(t *testing.T) {
	if !isHex64(idA) {
		t.Fatalf("idA should be recognized as 64-hex")
	}
	if isHex64(idA[:63]) {
		t.Fatalf("63 chars must not be 64-hex")
	}
	if isHex64(idA[:63] + "G") {
		t.Fatalf("non-hex char must not be 64-hex")
	}
	if isHex64("") {
		t.Fatalf("empty must not be 64-hex")
	}
}
