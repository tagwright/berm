// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package delivery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tagwright/berm/internal/wire"
)

// Volume is the fallback mechanism for both runtimes with no image change. It
// populates a tmpfs-backed named volume (not a bare tmpfs mount, which is not
// shareable between containers) and a waiter service uses the atomic appearance
// of the delivered manifest as its ready signal, closing the container-start
// race. Files only: like the hook, it cannot control the process environment,
// so a plan carrying env deliveries is rejected with ErrEnvUnsupported.
//
// The daemon mounts the same named volume the app container mounts, so writing
// into the volume from the daemon side lands the secret where the app will read
// it. ApplyVolume is the library function the daemon event loop calls; Deliver
// is the Delivery-interface wrapper over it. The volume MUST be tmpfs-backed:
// the operator declares it as a named volume with driver_opts type=tmpfs (or an
// equivalent tmpfs mount), and ApplyVolume refuses a non-tmpfs target through
// the shared tmpfs writer, so a secret never lands on persistent disk.
type Volume struct {
	opener    Opener
	mountPath string
	now       func() time.Time
}

// NewVolume builds the tmpfs-volume delivery over opener, writing into the
// daemon-side mount path of the shared named volume. The clock defaults to
// time.Now and is swappable in a test through the exported ApplyVolume.
func NewVolume(opener Opener, mountPath string) *Volume {
	return &Volume{opener: opener, mountPath: mountPath, now: time.Now}
}

// Mechanism satisfies Delivery.
func (v *Volume) Mechanism() Mechanism { return MechVolume }

// SupportsEnv satisfies Delivery. The volume mechanism cannot set env.
func (v *Volume) SupportsEnv() bool { return false }

// Deliver satisfies Delivery by delegating to ApplyVolume. A plan with env
// deliveries is rejected with ErrEnvUnsupported (ApplyVolume enforces this too,
// this is the interface-level statement of the gate).
func (v *Volume) Deliver(ctx context.Context, plan Plan) error {
	return ApplyVolume(ctx, plan, v.opener, v.mountPath, v.now())
}

var _ Delivery = (*Volume)(nil)

// volumeContainerRoot is the in-container mount point volume mode assumes for
// the shared named volume: the directory the manifest lands in. Every file and
// render path in a volume-mode plan must live under this root, because the
// shared volume covers exactly this mount point inside the container. A path
// outside it cannot be delivered by the volume, and ApplyVolume refuses it
// rather than write somewhere the container cannot see.
//
// This is the /run/berm convention (DefaultManifestPath's directory). An
// operator who mounts the volume elsewhere and sets custom paths under a
// different root is a v1 non-goal; the deploy docs (a later chunk) settle the
// mount-point contract.
var volumeContainerRoot = filepath.Dir(wire.DefaultManifestPath)

// ApplyVolume writes a plan's FILE and RENDER deliveries into the tmpfs named
// volume mounted at volumeMountPath on the daemon side, then writes the manifest
// LAST and atomically, because the manifest's atomic appearance is the waiter's
// ready signal: it exists only once every declared secret is in place.
//
// Files only. A plan carrying env bindings is refused with ErrEnvUnsupported:
// env is impossible in volume mode, which cannot control the process
// environment. The non-secret _FILE pointer for each file delivery is recorded
// in the manifest (volume mode cannot set env), so the app reads its pointer
// from the manifest or the well-known path.
//
// The volume must be tmpfs-backed: every write goes through the shared tmpfs
// writer with tmpfs enforcement on, so a non-tmpfs volumeMountPath is refused
// before any plaintext is produced. now is the manifest timestamp clock.
func ApplyVolume(ctx context.Context, plan Plan, opener Opener, volumeMountPath string, now time.Time) error {
	return applyVolume(ctx, plan, opener, volumeMountPath, now, true)
}

// applyVolume is ApplyVolume with the tmpfs-enforcement flag exposed. Production
// (ApplyVolume) always enforces tmpfs. A unit test on a host without a tmpfs
// mount may clear it, at the cost of that one guarantee, and must say so.
func applyVolume(ctx context.Context, plan Plan, opener Opener, volumeMountPath string, now time.Time, requireTmpfs bool) error {
	if len(plan.Env) > 0 {
		return fmt.Errorf("delivery: %w (mechanism %q)", ErrEnvUnsupported, plan.Mechanism)
	}
	if volumeMountPath == "" {
		return errors.New("delivery: volume mount path is empty")
	}

	// Files and renders first. The manifest is written only after every one of
	// these succeeds, so the ready signal never appears over a partial delivery.
	for _, ft := range plan.Files {
		dst, err := rebaseIntoVolume(ft.Path, volumeMountPath)
		if err != nil {
			return fmt.Errorf("delivery: volume file %q: %w", ft.Name, err)
		}
		rebased := ft
		rebased.Path = dst
		if err := WriteFile(ctx, opener, rebased, requireTmpfs); err != nil {
			return err
		}
	}
	for _, rt := range plan.Renders {
		dst, err := rebaseIntoVolume(rt.Path, volumeMountPath)
		if err != nil {
			return fmt.Errorf("delivery: volume render: %w", err)
		}
		rebased := rt
		rebased.Path = dst
		if err := WriteRender(ctx, opener, rebased, requireTmpfs); err != nil {
			return err
		}
	}

	// Manifest LAST, atomically, as the ready signal. Its in-manifest paths stay
	// the container-side paths (the app's view); only the write destination is
	// rebased into the daemon-side mount.
	m, err := BuildManifest(plan, opener, now)
	if err != nil {
		return err
	}
	data, err := m.Marshal()
	if err != nil {
		return err
	}
	manDst, err := rebaseIntoVolume(DefaultManifestPath, volumeMountPath)
	if err != nil {
		return fmt.Errorf("delivery: volume manifest path: %w", err)
	}
	if err := WriteManifest(manDst, data, requireTmpfs); err != nil {
		return err
	}
	return nil
}

// rebaseIntoVolume maps a container-absolute delivery path to its destination
// under the daemon-side volume mount, by stripping the assumed in-container
// volume root and rejoining under volumeMountPath. A path that does not live
// under the volume root is refused: volume mode can only place files inside the
// shared volume.
func rebaseIntoVolume(containerPath, volumeMountPath string) (string, error) {
	rel, err := filepath.Rel(volumeContainerRoot, filepath.Clean(containerPath))
	if err != nil {
		return "", fmt.Errorf("cannot rebase %q under %q: %w", containerPath, volumeContainerRoot, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is not under the volume mount root %q, so volume mode cannot deliver it", containerPath, volumeContainerRoot)
	}
	return filepath.Join(volumeMountPath, rel), nil
}

// ManifestReady is the volume waiter's ready-signal check. It returns true once
// the manifest at path exists and parses, false while it is absent, and a
// non-nil error only if a present manifest cannot be parsed (a real corruption,
// since the write is atomic temp-then-rename so a present file is always
// complete). A waiter entrypoint or the berm-client wait subcommand polls this
// until it returns true. The manifest carries names, paths, and ciphertext
// hashes, never a secret value, so reading it here leaks nothing.
func ManifestReady(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("delivery: read manifest for ready check: %w", err)
	}
	if _, err := ParseManifest(data); err != nil {
		return false, err
	}
	return true, nil
}
