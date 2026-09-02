// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package label

import (
	"testing"

	"github.com/tagwright/berm/internal/delivery"
)

// wantErr asserts err is a classified *Error of the given class and stickiness.
func wantErr(t *testing.T, err error, class Class) *Error {
	t.Helper()
	if err == nil {
		t.Fatalf("want %s error, got nil", class)
	}
	e, ok := AsError(err)
	if !ok {
		t.Fatalf("want classified *Error, got %T: %v", err, err)
	}
	if e.Class != class {
		t.Fatalf("want class %s, got %s (%v)", class, e.Class, e)
	}
	if e.Class.Sticky() != class.Sticky() {
		t.Fatalf("stickiness mismatch for %s", class)
	}
	return e
}

func TestParseRef(t *testing.T) {
	cases := []struct {
		in   string
		kind RefKind
		src  string
		key  string
		bad  bool
	}{
		{in: "POSTGRES_PASSWORD", kind: RefKey, key: "POSTGRES_PASSWORD"},
		{in: "API_KEY_2", kind: RefKey, key: "API_KEY_2"},
		{in: "_LEADING", kind: RefKey, key: "_LEADING"},
		{in: "shared-db/DATABASE_URL", kind: RefSourceKey, src: "shared-db", key: "DATABASE_URL"},
		{in: "webapp-tls", kind: RefSource, src: "webapp-tls"},
		{in: "db1", kind: RefSource, src: "db1"},
		{in: "123", kind: RefSource, src: "123"},
		{in: "", bad: true},
		{in: "2LEADING", bad: true},       // key cannot lead with a digit and is not source-shaped with uppercase
		{in: "Mixed_Case", bad: true},     // neither a key (has lowercase) nor a source (has uppercase)
		{in: "a/b/c", bad: true},          // more than one separator
		{in: "UPPER/lowerkey", bad: true}, // source half must be lowercase, key half uppercase
		{in: "src/lower", bad: true},      // key half must be uppercase
		{in: "-lead/KEY", bad: true},      // source cannot lead with a dash
		{in: "/KEY", bad: true},           // empty source
		{in: "src/", bad: true},           // empty key
	}
	for _, c := range cases {
		ref, err := ParseRef(c.in)
		if c.bad {
			wantErr(t, err, ClassMalformed)
			continue
		}
		if err != nil {
			t.Fatalf("ParseRef(%q): unexpected error %v", c.in, err)
		}
		if ref.Kind != c.kind || ref.Source != c.src || ref.Key != c.key {
			t.Errorf("ParseRef(%q) = %+v, want kind %v src %q key %q", c.in, ref, c.kind, c.src, c.key)
		}
	}
}

func TestParseDisabledIsInert(t *testing.T) {
	for _, labels := range []map[string]string{
		{},
		{"berm.enable": "false"},
		{"berm.file.x.from": "KEY"}, // no enable at all
		{"berm.enable": "false", "berm.rotate": "x"}, // even a reserved label is inert when disabled
	} {
		spec, err := Parse(labels)
		if err != nil {
			t.Fatalf("disabled container should not error: %v", err)
		}
		if spec.Enabled {
			t.Fatalf("spec should be inert for %v", labels)
		}
	}
}

func TestParseCrossPrefixConflict(t *testing.T) {
	// Different values under the two doorways is an error.
	_, err := Parse(map[string]string{
		"berm.enable":             "true",
		"berm.source":             "one",
		"tagwright.secret.source": "two",
	})
	wantErr(t, err, ClassCrossPrefixConflict)

	// Same value under both doorways is harmless.
	spec, err := Parse(map[string]string{
		"berm.enable":             "true",
		"berm.source":             "same",
		"tagwright.secret.source": "same",
	})
	if err != nil {
		t.Fatalf("same value under both prefixes should be harmless: %v", err)
	}
	if spec.Source != "same" {
		t.Fatalf("source: want same, got %q", spec.Source)
	}
}

func TestParseBothDoorwaysIdenticalSpec(t *testing.T) {
	primary, err := Parse(map[string]string{
		"berm.enable":           "true",
		"berm.file.pgpass.from": "POSTGRES_PASSWORD",
	})
	if err != nil {
		t.Fatal(err)
	}
	alias, err := Parse(map[string]string{
		"tagwright.secret.enable":           "true",
		"tagwright.secret.file.pgpass.from": "POSTGRES_PASSWORD",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(primary.Files) != 1 || len(alias.Files) != 1 || primary.Files[0] != alias.Files[0] {
		t.Fatalf("two doorways parsed to different specs: %+v vs %+v", primary, alias)
	}
}

func TestParseUnknownSuffix(t *testing.T) {
	for _, k := range []string{
		"berm.fille.db.path", // classic typo
		"berm.bogus",
		"berm.file.pgpass.badattr", // unknown file attribute
		"berm.file.pgpass",         // file with no attribute
	} {
		_, err := Parse(map[string]string{"berm.enable": "true", k: "v"})
		wantErr(t, err, ClassUnknownSuffix)
	}
}

func TestParseRotateReserved(t *testing.T) {
	_, err := Parse(map[string]string{"berm.enable": "true", "berm.rotate": "on"})
	wantErr(t, err, ClassRotateReserved)
}

func TestParseEnvNoAckIsHardAndSticky(t *testing.T) {
	for _, envLabel := range []map[string]string{
		{"berm.env": "all"},
		{"berm.env": "API_KEY"},
		{"berm.env.DATABASE_URL": "shared/DATABASE_URL"},
	} {
		labels := map[string]string{"berm.enable": "true"}
		for k, v := range envLabel {
			labels[k] = v
		}
		e := wantErr(t, mustErr(Parse(labels)), ClassEnvNoAck)
		if !e.Sticky() {
			t.Fatalf("env-no-ack must be sticky")
		}
	}

	// With the acknowledgment, the same labels parse.
	spec, err := Parse(map[string]string{
		"berm.enable":          "true",
		"berm.env":             "all",
		"berm.env.acknowledge": "true",
	})
	if err != nil {
		t.Fatalf("env with ack should parse: %v", err)
	}
	if !spec.EnvAck || len(spec.Env) != 1 || !spec.Env[0].All {
		t.Fatalf("env=all with ack parsed wrong: %+v", spec)
	}
}

func TestParseMalformedValues(t *testing.T) {
	cases := map[string]string{
		"berm.delivery":     "carrier-pigeon",
		"berm.owner":        "root",
		"berm.mode":         "rwxr--r--",
		"berm.dotenv":       "relative/path",
		"berm.envdir":       "also/relative",
		"berm.source":       "Not_A_Source",
		"berm.file.x.owner": "nobody",
		"berm.file.x.mode":  "999999",
		"berm.file.x.path":  "relative",
		"berm.file.x.from":  "bad ref",
	}
	for k, v := range cases {
		_, err := Parse(map[string]string{"berm.enable": "true", k: v})
		wantErr(t, err, ClassMalformed)
	}
}

func TestParseEnvBareSourceRefRejected(t *testing.T) {
	// A whole-source ref in env has no key to name the var.
	_, err := Parse(map[string]string{
		"berm.enable":          "true",
		"berm.env":             "somebinary",
		"berm.env.acknowledge": "true",
	})
	wantErr(t, err, ClassWrongRefShape)

	_, err = Parse(map[string]string{
		"berm.enable":          "true",
		"berm.env.TLS":         "webapp-tls",
		"berm.env.acknowledge": "true",
	})
	wantErr(t, err, ClassWrongRefShape)
}

func TestParseFullSpec(t *testing.T) {
	spec, err := Parse(map[string]string{
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
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Delivery != delivery.MechClient || spec.Source != "webapp" || spec.Owner != "1000:1000" || spec.Mode != "0400" {
		t.Fatalf("core fields wrong: %+v", spec)
	}
	if len(spec.Env) != 1 || spec.Env[0].Var != "DATABASE_URL" || spec.Env[0].Ref.Source != "shared-db" || spec.Env[0].Ref.Key != "DATABASE_URL" {
		t.Fatalf("env wrong: %+v", spec.Env)
	}
	if len(spec.Files) != 1 {
		t.Fatalf("want 1 file, got %+v", spec.Files)
	}
	f := spec.Files[0]
	if f.Name != "tls-key" || f.From.Kind != RefSource || f.From.Source != "webapp-tls" || f.Path != "/run/berm/tls/server.key" || f.Owner != "1000:1000" || f.Mode != "0440" {
		t.Fatalf("file wrong: %+v", f)
	}
}

// mustErr adapts the (spec, err) pair for wantErr in a loop.
func mustErr(_ ContainerSpec, err error) error { return err }
