// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package delivery

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tagwright/berm/internal/backend"
)

// fullVolumePlan is a files-only plan (no env, as volume mode requires): a
// dotenv-key file with a pointer, a binary whole file, and a dotenv render.
// Every path lives under the /run/berm volume root.
func fullVolumePlan() Plan {
	return Plan{
		Container: "vol123",
		Service:   "webapp",
		Mechanism: MechVolume,
		Files: []FileTarget{
			{Name: "pgpass", Source: "webapp", Format: backend.FormatDotenv, Key: "DB_PASSWORD",
				Path: "/run/berm/pgpass", Owner: "1000:1000", Mode: "0400", PointerVar: "DB_PASSWORD_FILE"},
			{Name: "tls", Source: "webapp-tls", Format: backend.FormatBinary, Whole: true,
				Path: "/run/berm/tls/server.key", Owner: "1000:1000", Mode: "0440"},
		},
		Renders: []RenderTarget{
			{Kind: RenderDotenv, Source: "webapp", Path: "/run/berm/all.env", Owner: "0:0", Mode: "0400"},
		},
	}
}

// manifestPathIn returns the daemon-side manifest path for a volume mounted at
// mountPath, mirroring rebaseIntoVolume of DefaultManifestPath.
func manifestPathIn(mountPath string) string {
	return filepath.Join(mountPath, "manifest")
}

func TestApplyVolumeWritesFilesAndManifestLast(t *testing.T) {
	dir, req := tmpfsTestDir(t)
	manPath := manifestPathIn(dir)

	// Ready signal is false before delivery: no manifest yet.
	if ready, err := ManifestReady(manPath); err != nil || ready {
		t.Fatalf("ManifestReady before apply = (%v, %v), want (false, nil)", ready, err)
	}

	plan := fullVolumePlan()
	if err := applyVolume(context.Background(), plan, testFixture(), dir, time.Unix(1_700_000_000, 0), req); err != nil {
		t.Fatalf("applyVolume: %v", err)
	}

	// Each delivered file lands rebased under the volume mount, byte-correct.
	want := map[string][]byte{
		"pgpass":         []byte("p=ss w0rd!"),
		"tls/server.key": {0x00, 0x01, 0xff, 0xfe, 'K', 'E', 'Y', '\n', 0x80},
		"all.env":        []byte("DB_PASSWORD=p=ss w0rd!\nAPI_URL=https://api.example/x?a=b&c=d\nSPECIAL=a#b$c%d\n"),
	}
	for rel, exp := range want {
		got, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatalf("read %q: %v", rel, err)
		}
		if !bytes.Equal(got, exp) {
			t.Errorf("file %q = %q, want %q", rel, got, exp)
		}
	}

	// Manifest present and parseable: the ready signal has flipped.
	if ready, err := ManifestReady(manPath); err != nil || !ready {
		t.Fatalf("ManifestReady after apply = (%v, %v), want (true, nil)", ready, err)
	}

	// Manifest carries NO secret value, but records the pointer and ciphertext
	// hashes.
	manData, err := os.ReadFile(manPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	assertNoLeak(t, "volume manifest", manData)
	for _, want := range []string{"DB_PASSWORD_FILE", "sha256:1111", "sha256:2222", "/run/berm/pgpass"} {
		if !bytes.Contains(manData, []byte(want)) {
			t.Errorf("manifest missing %q:\n%s", want, manData)
		}
	}
}

// TestApplyVolumeManifestNotWrittenOnFileFailure proves the manifest is written
// LAST: if a file delivery fails, the manifest never appears and the ready
// signal never flips, so a waiter does not release over a partial delivery.
func TestApplyVolumeManifestNotWrittenOnFileFailure(t *testing.T) {
	dir, req := tmpfsTestDir(t)
	manPath := manifestPathIn(dir)

	plan := fullVolumePlan()
	// Point one file at a source the opener does not know, so its write fails
	// after any earlier files may have landed.
	plan.Files[1].Source = "nonexistent-source"

	err := applyVolume(context.Background(), plan, testFixture(), dir, time.Unix(1_700_000_000, 0), req)
	if err == nil {
		t.Fatal("expected an error when a file source is missing")
	}
	if ready, rerr := ManifestReady(manPath); rerr != nil || ready {
		t.Fatalf("ready signal must stay false on a failed delivery, got (%v, %v)", ready, rerr)
	}
}

// TestApplyVolumeRefusesEnv proves env is impossible in volume mode.
func TestApplyVolumeRefusesEnv(t *testing.T) {
	dir, req := tmpfsTestDir(t)
	plan := fullVolumePlan()
	plan.Env = []EnvTarget{{Var: "X", Source: "webapp", Key: "DB_PASSWORD"}}
	err := applyVolume(context.Background(), plan, testFixture(), dir, time.Now(), req)
	if !errors.Is(err, ErrEnvUnsupported) {
		t.Fatalf("applyVolume with env = %v, want ErrEnvUnsupported", err)
	}
}

// TestApplyVolumeRefusesPathOutsideVolume proves a file whose path is not under
// the shared volume root is refused rather than written somewhere the container
// cannot see.
func TestApplyVolumeRefusesPathOutsideVolume(t *testing.T) {
	dir, req := tmpfsTestDir(t)
	plan := fullVolumePlan()
	plan.Files = []FileTarget{
		{Name: "escape", Source: "webapp", Format: backend.FormatDotenv, Key: "DB_PASSWORD",
			Path: "/etc/secret", Owner: "0:0", Mode: "0400"},
	}
	plan.Renders = nil
	if err := applyVolume(context.Background(), plan, testFixture(), dir, time.Now(), req); err == nil {
		t.Fatal("expected a refusal for a path outside the volume root")
	}
}

// TestManifestReadyOnCorruptManifest proves a present-but-unparseable manifest
// surfaces as an error, not a false ready.
func TestManifestReadyOnCorruptManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest")
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o444); err != nil {
		t.Fatal(err)
	}
	ready, err := ManifestReady(path)
	if ready {
		t.Error("a corrupt manifest must not read as ready")
	}
	if err == nil {
		t.Error("a corrupt manifest must surface an error")
	}
}
