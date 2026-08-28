// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package resolve

import (
	"reflect"
	"testing"

	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/delivery"
	"github.com/tagwright/berm/internal/label"
)

// testConfig is the berm.yml the worked examples and error cases resolve
// against. It carries the three worked-example sources plus a few sources
// shaped for the error-class tests. Nothing in it is a secret value.
func testConfig() *config.Config {
	return &config.Config{
		Sources: map[string]config.Source{
			// Worked-example sources.
			"firefly-db": {Format: "dotenv"},
			"paperless":  {Format: "dotenv"},
			"webapp":     {Format: "dotenv"},
			// webapp-tls is owned by webapp explicitly. Under the frozen strict
			// exact-name rule its owner does NOT default to webapp from the shared
			// name prefix, so the grant is expressed with owner: webapp.
			"webapp-tls": {Format: "binary", Owner: "webapp"},
			"shared-db":  {Format: "dotenv", Owner: "postgres", Access: []string{"webapp", "reporter"}},
			// Error-class sources.
			"tlsbin": {Format: "binary"}, // service tlsbin owns its same-named source
			// webapp-cache is named under the webapp- prefix but has no owner and no
			// grant. Under the removed prefix rule webapp would have owned it; under
			// the strict exact-name rule its owner defaults to "webapp-cache", so
			// webapp may not read it. This proves the prefix loophole is closed.
			"webapp-cache": {Format: "dotenv"},
			"billing":      {Format: "dotenv", Owner: "billing"}, // owned by another service, no grant
		},
		Defaults: config.Defaults{},
	}
}

// wantErr asserts err is a classified *label.Error of the given class and
// stickiness.
func wantErr(t *testing.T, plan *Plan, err error, class label.Class) *label.Error {
	t.Helper()
	if plan != nil {
		t.Fatalf("want nil plan on error, got %+v", plan)
	}
	if err == nil {
		t.Fatalf("want %s error, got nil", class)
	}
	e, ok := label.AsError(err)
	if !ok {
		t.Fatalf("want classified *label.Error, got %T: %v", err, err)
	}
	if e.Class != class {
		t.Fatalf("want class %s, got %s (%v)", class, e.Class, e)
	}
	if e.Sticky() != class.Sticky() {
		t.Fatalf("stickiness mismatch: class %s Sticky()=%v", class, e.Sticky())
	}
	return e
}

// --- Worked examples --------------------------------------------------------

func TestWorkedExampleA_CanonicalMinimalFile(t *testing.T) {
	got, err := Resolve(Input{
		Labels: map[string]string{
			"berm.enable":           "true",
			"berm.file.pgpass.from": "POSTGRES_PASSWORD",
		},
		ContainerID:     "c-firefly",
		Service:         "firefly-db",
		Config:          testConfig(),
		DefaultDelivery: delivery.MechClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := &Plan{
		Container: "c-firefly",
		Service:   "firefly-db",
		Mechanism: delivery.MechClient,
		Files: []FileBinding{{
			Name:       "pgpass",
			Source:     "firefly-db",
			Format:     backend.FormatDotenv,
			Whole:      false,
			Key:        "POSTGRES_PASSWORD",
			Path:       "/run/berm/pgpass",
			Owner:      "0:0",
			Mode:       "0400",
			PointerVar: "POSTGRES_PASSWORD_FILE",
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plan mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestWorkedExampleB_EnvAllWithAcknowledge(t *testing.T) {
	got, err := Resolve(Input{
		Labels: map[string]string{
			"berm.enable":          "true",
			"berm.delivery":        "client",
			"berm.env":             "all",
			"berm.env.acknowledge": "true",
		},
		ContainerID:     "c-paperless",
		Service:         "paperless",
		Config:          testConfig(),
		DefaultDelivery: delivery.MechClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := &Plan{
		Container:   "c-paperless",
		Service:     "paperless",
		Mechanism:   delivery.MechClient,
		Env:         []EnvBinding{{All: true, Source: "paperless"}},
		EnvExposure: true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plan mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestWorkedExampleC_FullSpread(t *testing.T) {
	got, err := Resolve(Input{
		Labels: map[string]string{
			"berm.enable":             "true",
			"berm.delivery":           "client",
			"berm.source":             "webapp",
			"berm.owner":              "1000:1000",
			"berm.mode":               "0400",
			"berm.env.DATABASE_URL":   "shared-db/DATABASE_URL",
			"berm.env.acknowledge":    "true",
			"berm.file.tls-key.from":  "webapp-tls",
			"berm.file.tls-key.path":  "/run/berm/tls/server.key",
			"berm.file.tls-key.owner": "1000:1000",
			"berm.file.tls-key.mode":  "0440",
		},
		ContainerID:     "c-webapp",
		Service:         "webapp",
		ContainerUser:   "1000:1000",
		Config:          testConfig(),
		DefaultDelivery: delivery.MechClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := &Plan{
		Container:   "c-webapp",
		Service:     "webapp",
		Mechanism:   delivery.MechClient,
		Env:         []EnvBinding{{Var: "DATABASE_URL", Source: "shared-db", Key: "DATABASE_URL"}},
		EnvExposure: true,
		Files: []FileBinding{{
			Name:       "tls-key",
			Source:     "webapp-tls",
			Format:     backend.FormatBinary,
			Whole:      true,
			Key:        "",
			Path:       "/run/berm/tls/server.key",
			Owner:      "1000:1000",
			Mode:       "0440",
			PointerVar: "",
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plan mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestBothDoorwaysIdenticalPlan(t *testing.T) {
	base := func(prefix string) *Plan {
		p, err := Resolve(Input{
			Labels: map[string]string{
				prefix + "enable":           "true",
				prefix + "file.pgpass.from": "POSTGRES_PASSWORD",
			},
			ContainerID:     "c-firefly",
			Service:         "firefly-db",
			Config:          testConfig(),
			DefaultDelivery: delivery.MechClient,
		})
		if err != nil {
			t.Fatalf("%s: %v", prefix, err)
		}
		return p
	}
	if !reflect.DeepEqual(base("berm."), base("tagwright.secret.")) {
		t.Fatal("the two doorways produced different resolved plans")
	}
}

// --- Inert and whole-source renders ----------------------------------------

func TestInertContainerNoPlanNoError(t *testing.T) {
	plan, err := Resolve(Input{
		Labels:          map[string]string{"berm.file.x.from": "KEY"}, // no enable
		Service:         "x",
		Config:          testConfig(),
		DefaultDelivery: delivery.MechClient,
	})
	if plan != nil || err != nil {
		t.Fatalf("inert container: want (nil, nil), got (%+v, %v)", plan, err)
	}
}

func TestWholeSourceRenders(t *testing.T) {
	got, err := Resolve(Input{
		Labels: map[string]string{
			"berm.enable": "true",
			"berm.dotenv": "/run/berm/app.env",
			"berm.envdir": "/run/berm/env.d",
			"berm.mode":   "0440",
		},
		ContainerID:     "c-firefly",
		Service:         "firefly-db",
		Config:          testConfig(),
		DefaultDelivery: delivery.MechHook,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []RenderBinding{
		{Kind: RenderDotenv, Source: "firefly-db", Format: backend.FormatDotenv, Path: "/run/berm/app.env", Owner: "0:0", Mode: "0440"},
		{Kind: RenderEnvdir, Source: "firefly-db", Format: backend.FormatDotenv, Path: "/run/berm/env.d", Owner: "0:0", Mode: "0440"},
	}
	if !reflect.DeepEqual(got.Renders, want) {
		t.Fatalf("renders mismatch:\n got %+v\nwant %+v", got.Renders, want)
	}
}

// --- Container-level owner and mode on file deliveries ----------------------

// TestFileInheritsContainerOwnerMode asserts that berm.owner / berm.mode set on
// the container become the default owner and mode for a berm.file.<name>
// delivery that omits its own owner and mode. This is the middle default tier
// from the frozen grammar: per-file override, else container-level, else the
// built-in fallback.
func TestFileInheritsContainerOwnerMode(t *testing.T) {
	got, err := Resolve(Input{
		Labels: map[string]string{
			"berm.enable":           "true",
			"berm.owner":            "1000:1000",
			"berm.mode":             "0440",
			"berm.file.pgpass.from": "POSTGRES_PASSWORD",
		},
		ContainerID:     "c-firefly",
		Service:         "firefly-db",
		Config:          testConfig(),
		DefaultDelivery: delivery.MechClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 1 {
		t.Fatalf("want one file, got %+v", got.Files)
	}
	if got.Files[0].Owner != "1000:1000" {
		t.Fatalf("want container-level owner 1000:1000, got %q", got.Files[0].Owner)
	}
	if got.Files[0].Mode != "0440" {
		t.Fatalf("want container-level mode 0440, got %q", got.Files[0].Mode)
	}
}

// TestFilePerFileOwnerModeOverridesContainer asserts that a per-file
// berm.file.<name>.owner / .mode wins over the container-level berm.owner /
// berm.mode default.
func TestFilePerFileOwnerModeOverridesContainer(t *testing.T) {
	got, err := Resolve(Input{
		Labels: map[string]string{
			"berm.enable":            "true",
			"berm.owner":             "1000:1000",
			"berm.mode":              "0440",
			"berm.file.pgpass.from":  "POSTGRES_PASSWORD",
			"berm.file.pgpass.owner": "2000:2000",
			"berm.file.pgpass.mode":  "0400",
		},
		ContainerID:     "c-firefly",
		Service:         "firefly-db",
		Config:          testConfig(),
		DefaultDelivery: delivery.MechClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 1 {
		t.Fatalf("want one file, got %+v", got.Files)
	}
	if got.Files[0].Owner != "2000:2000" {
		t.Fatalf("want per-file owner 2000:2000 to win, got %q", got.Files[0].Owner)
	}
	if got.Files[0].Mode != "0400" {
		t.Fatalf("want per-file mode 0400 to win, got %q", got.Files[0].Mode)
	}
}

// TestFileBuiltinFallbackWhenNoContainerOwnerMode asserts that with neither a
// per-file nor a container-level owner or mode, the built-in fallback still
// applies: the container's configured user (else 0:0) for owner, and
// defaults.mode (else 0400) for mode.
func TestFileBuiltinFallbackWhenNoContainerOwnerMode(t *testing.T) {
	got, err := Resolve(Input{
		Labels: map[string]string{
			"berm.enable":           "true",
			"berm.file.pgpass.from": "POSTGRES_PASSWORD",
		},
		ContainerID:     "c-firefly",
		Service:         "firefly-db",
		Config:          testConfig(),
		DefaultDelivery: delivery.MechClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 1 {
		t.Fatalf("want one file, got %+v", got.Files)
	}
	if got.Files[0].Owner != "0:0" {
		t.Fatalf("want built-in fallback owner 0:0, got %q", got.Files[0].Owner)
	}
	if got.Files[0].Mode != "0400" {
		t.Fatalf("want built-in fallback mode 0400, got %q", got.Files[0].Mode)
	}
}

// --- Error classes, one per case -------------------------------------------

func TestErrorBareRefAgainstDotenv(t *testing.T) {
	// A whole-source (bare source) ref against a dotenv source.
	plan, err := Resolve(Input{
		Labels:      map[string]string{"berm.enable": "true", "berm.file.x.from": "webapp"},
		ContainerID: "c", Service: "webapp", Config: testConfig(), DefaultDelivery: delivery.MechClient,
	})
	wantErr(t, plan, err, label.ClassWrongRefShape)
}

func TestErrorSourceKeyAgainstBinary(t *testing.T) {
	// A source/KEY ref against a binary source. tlsbin has no explicit owner, so
	// its effective owner defaults to its own name "tlsbin", which equals the
	// service identity, so tlsbin owns it and we reach the format check.
	plan, err := Resolve(Input{
		Labels:      map[string]string{"berm.enable": "true", "berm.file.x.from": "tlsbin/PRIVATE_KEY"},
		ContainerID: "c", Service: "tlsbin", Config: testConfig(), DefaultDelivery: delivery.MechClient,
	})
	wantErr(t, plan, err, label.ClassWrongRefShape)
}

func TestErrorNonexistentSource(t *testing.T) {
	// A bare KEY resolves against the default source, which does not exist.
	plan, err := Resolve(Input{
		Labels:      map[string]string{"berm.enable": "true", "berm.file.x.from": "SOME_KEY"},
		ContainerID: "c", Service: "ghost-service", Config: testConfig(), DefaultDelivery: delivery.MechClient,
	})
	e := wantErr(t, plan, err, label.ClassMissingSource)
	if !e.Sticky() {
		t.Fatal("missing source must be sticky")
	}
}

func TestErrorUngrantedCrossServiceRefIsSticky(t *testing.T) {
	// webapp references billing/KEY. billing is owned by service "billing" and
	// grants no one, so webapp is not permitted.
	plan, err := Resolve(Input{
		Labels:      map[string]string{"berm.enable": "true", "berm.file.x.from": "billing/AMOUNT"},
		ContainerID: "c", Service: "webapp", Config: testConfig(), DefaultDelivery: delivery.MechClient,
	})
	e := wantErr(t, plan, err, label.ClassUngrantedRef)
	if !e.Sticky() {
		t.Fatal("ungranted ref must be sticky")
	}
}

func TestErrorPrefixOwnershipLoopholeClosed(t *testing.T) {
	// webapp references webapp-cache/KEY. Under the removed "<service>-" prefix
	// ownership rule webapp would have owned webapp-cache for free. Under the
	// frozen strict exact-name rule webapp-cache's effective owner is
	// "webapp-cache" (its own name, no explicit owner), which is not webapp, and
	// its access list names no one, so webapp may not read it. The result is a
	// sticky ungranted error, proving the prefix loophole is gone.
	plan, err := Resolve(Input{
		Labels:      map[string]string{"berm.enable": "true", "berm.file.x.from": "webapp-cache/API_KEY"},
		ContainerID: "c", Service: "webapp", Config: testConfig(), DefaultDelivery: delivery.MechClient,
	})
	e := wantErr(t, plan, err, label.ClassUngrantedRef)
	if !e.Sticky() {
		t.Fatal("ungranted prefix-named ref must be sticky")
	}
}

func TestErrorEnvNoAckHardAndSticky(t *testing.T) {
	plan, err := Resolve(Input{
		Labels:      map[string]string{"berm.enable": "true", "berm.delivery": "client", "berm.env": "all"},
		ContainerID: "c", Service: "paperless", Config: testConfig(), DefaultDelivery: delivery.MechClient,
	})
	e := wantErr(t, plan, err, label.ClassEnvNoAck)
	if !e.Sticky() {
		t.Fatal("env-no-ack must be sticky")
	}
}

func TestErrorEnvUnderHookAndVolumeRefused(t *testing.T) {
	for _, mech := range []string{"hook", "volume"} {
		plan, err := Resolve(Input{
			Labels: map[string]string{
				"berm.enable":          "true",
				"berm.delivery":        mech,
				"berm.env":             "all",
				"berm.env.acknowledge": "true",
			},
			ContainerID: "c", Service: "paperless", Config: testConfig(), DefaultDelivery: delivery.MechClient,
		})
		wantErr(t, plan, err, label.ClassEnvWrongMechanism)
	}
}

func TestErrorAllAcrossGrantIllegal(t *testing.T) {
	// webapp sets its default source to shared-db (owned by postgres, webapp is
	// granted read). all is still illegal because it is not the owner.
	plan, err := Resolve(Input{
		Labels: map[string]string{
			"berm.enable":          "true",
			"berm.delivery":        "client",
			"berm.source":          "shared-db",
			"berm.env":             "all",
			"berm.env.acknowledge": "true",
		},
		ContainerID: "c", Service: "webapp", Config: testConfig(), DefaultDelivery: delivery.MechClient,
	})
	wantErr(t, plan, err, label.ClassAllCrossService)
}

func TestAllOnOwnedSourceLegal(t *testing.T) {
	// The mirror of the illegal case: all on the container's own owned default
	// source resolves.
	got, err := Resolve(Input{
		Labels: map[string]string{
			"berm.enable":          "true",
			"berm.delivery":        "client",
			"berm.env":             "all",
			"berm.env.acknowledge": "true",
		},
		ContainerID: "c", Service: "paperless", Config: testConfig(), DefaultDelivery: delivery.MechClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Env) != 1 || !got.Env[0].All || got.Env[0].Source != "paperless" || !got.EnvExposure {
		t.Fatalf("all on owned source resolved wrong: %+v", got)
	}
}

func TestErrorRotateReserved(t *testing.T) {
	plan, err := Resolve(Input{
		Labels:      map[string]string{"berm.enable": "true", "berm.rotate": "on"},
		ContainerID: "c", Service: "webapp", Config: testConfig(), DefaultDelivery: delivery.MechClient,
	})
	wantErr(t, plan, err, label.ClassRotateReserved)
}

func TestErrorUnknownSuffix(t *testing.T) {
	plan, err := Resolve(Input{
		Labels:      map[string]string{"berm.enable": "true", "berm.fille.db.path": "/x"},
		ContainerID: "c", Service: "webapp", Config: testConfig(), DefaultDelivery: delivery.MechClient,
	})
	wantErr(t, plan, err, label.ClassUnknownSuffix)
}

func TestErrorCrossPrefixConflict(t *testing.T) {
	plan, err := Resolve(Input{
		Labels: map[string]string{
			"berm.enable":             "true",
			"berm.source":             "webapp",
			"tagwright.secret.source": "paperless",
		},
		ContainerID: "c", Service: "webapp", Config: testConfig(), DefaultDelivery: delivery.MechClient,
	})
	wantErr(t, plan, err, label.ClassCrossPrefixConflict)
}

// --- Replicas share identity and grants ------------------------------------

func TestReplicasShareIdentityAndGrants(t *testing.T) {
	// Two replicas of webapp (same Service, different container IDs) both read
	// the granted cross-service source shared-db. Both succeed identically bar
	// the container ID, demonstrating shared identity and grants.
	mk := func(id string) *Plan {
		p, err := Resolve(Input{
			Labels: map[string]string{
				"berm.enable":       "true",
				"berm.file.db.from": "shared-db/DATABASE_URL",
			},
			ContainerID:     id,
			Service:         "webapp",
			Config:          testConfig(),
			DefaultDelivery: delivery.MechHook,
		})
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		return p
	}
	a, b := mk("replica-1"), mk("replica-2")
	if a.Files[0].Source != "shared-db" || b.Files[0].Source != "shared-db" {
		t.Fatalf("replicas did not both resolve the shared source: %+v %+v", a.Files, b.Files)
	}
	a.Container, b.Container = "", ""
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("replicas resolved differently: %+v vs %+v", a, b)
	}
}

// --- Delivery mechanism defaulting -----------------------------------------

func TestDeliveryDefaulting(t *testing.T) {
	// No berm.delivery, no BERM_DEFAULT_DELIVERY: fall back to the berm.yml
	// defaults block.
	cfg := testConfig()
	cfg.Defaults.Delivery = "volume"
	got, err := Resolve(Input{
		Labels:      map[string]string{"berm.enable": "true", "berm.file.x.from": "POSTGRES_PASSWORD"},
		ContainerID: "c", Service: "firefly-db", Config: cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Mechanism != delivery.MechVolume {
		t.Fatalf("want volume from berm.yml defaults, got %s", got.Mechanism)
	}

	// Nothing resolvable at all is a bad-config error.
	plan, err := Resolve(Input{
		Labels:      map[string]string{"berm.enable": "true", "berm.file.x.from": "POSTGRES_PASSWORD"},
		ContainerID: "c", Service: "firefly-db", Config: testConfig(),
	})
	wantErr(t, plan, err, label.ClassBadConfig)
}
