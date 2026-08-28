// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

//go:build integration

// This is the real crypto round-trip harness. It runs ONLY under the
// "integration" build tag and ONLY where the sops and age binaries are on PATH,
// because it drives them for real: it generates an age keypair with age-keygen,
// writes a .sops.yaml age rule, sops-encrypts a dotenv fixture and a binary
// fixture, then decrypts each back through the driver and byte-compares the
// result to the known plaintext. It also proves the failure paths error without
// leaking a value. Nothing here ships in the daemon binary.
//
// Run it with the pinned binaries installed:
//
//	go test -tags integration -buildvcs=false ./internal/backend/...
package backend

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// dotenvFixture is the known plaintext. The values deliberately exercise the
// edges the parser must round-trip byte for byte: leading and trailing spaces,
// literal double and single quotes, an embedded '=', shell-special characters,
// and a '#' that is not at line start (so it is value, not comment).
var dotenvFixture = []struct {
	key   string
	value string
}{
	{"SIMPLE", "hello"},
	{"SPACED", " has leading and trailing spaces "},
	{"QUOTED", `"double quoted"`},
	{"SINGLEQ", `'single quoted'`},
	{"WITHEQ", "postgres://user:p=ss@host:5432/db?sslmode=require"},
	{"SPECIAL", "a#b$c%d&e*f"},
	{"TRAILING", "trail   "},
}

// binaryFixture is a known raw payload with a NUL and high bytes, to prove the
// binary path is byte-exact and not text-mangled.
var binaryFixture = []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 'k', 'e', 'y', '\n', 0x7f, 0x80}

func requireTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("integration harness needs %q on PATH: %v", name, err)
	}
	return p
}

// genAgeKey writes a fresh age keypair to dir/name and returns the key file
// path and the age recipient (public key) parsed from the file.
func genAgeKey(t *testing.T, dir, name string) (keyPath, recipient string) {
	t.Helper()
	keyPath = filepath.Join(dir, name)
	cmd := exec.Command("age-keygen", "-o", keyPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("age-keygen: %v: %s", err, stderr.String())
	}
	f, err := os.Open(keyPath)
	if err != nil {
		t.Fatalf("open age key: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(strings.ToLower(line), "# public key:") {
			recipient = strings.TrimSpace(line[strings.IndexByte(line, ':')+1:])
		}
	}
	if recipient == "" {
		t.Fatal("could not parse age recipient from key file")
	}
	return keyPath, recipient
}

// sopsEncrypt encrypts plaintext of the given sops type ("dotenv" or "binary")
// to outPath, using a .sops.yaml in dir that names recipient. It runs sops with
// a minimal env, cwd=dir so the rule is discovered.
func sopsEncrypt(t *testing.T, dir, recipient, sopsType string, plaintext []byte, outPath string) {
	t.Helper()
	rule := "creation_rules:\n  - path_regex: .*\n    age: " + recipient + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".sops.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}
	plainPath := filepath.Join(dir, "plain."+sopsType+".in")
	if err := os.WriteFile(plainPath, plaintext, 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	cmd := exec.Command("sops", "-e", "--input-type", sopsType, "--output-type", sopsType, plainPath)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sops encrypt: %v: %s", err, stderr.String())
	}
	if err := os.WriteFile(outPath, out.Bytes(), 0o600); err != nil {
		t.Fatalf("write ciphertext: %v", err)
	}
}

// buildDotenvPlaintext renders the fixture the way a plaintext .env would look
// going into sops: one KEY=VALUE line per entry, values verbatim.
func buildDotenvPlaintext() []byte {
	var b bytes.Buffer
	for _, kv := range dotenvFixture {
		b.WriteString(kv.key)
		b.WriteByte('=')
		b.WriteString(kv.value)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// allSecretValues is every plaintext value, for the no-leak assertion.
func allSecretValues() []string {
	vals := make([]string, 0, len(dotenvFixture)+1)
	for _, kv := range dotenvFixture {
		if kv.value != "" {
			vals = append(vals, kv.value)
		}
	}
	vals = append(vals, string(binaryFixture))
	return vals
}

// assertNoLeak fails if s contains any known secret value. Used on every error
// string the failure-path tests produce, to prove the no-log discipline.
func assertNoLeak(t *testing.T, context, s string) {
	t.Helper()
	for _, v := range allSecretValues() {
		if len(v) >= 4 && strings.Contains(s, v) {
			t.Fatalf("%s leaked a secret value: %q", context, s)
		}
	}
}

func TestSOPSAgeRoundTrip(t *testing.T) {
	requireTool(t, "sops")
	requireTool(t, "age-keygen")

	dir := t.TempDir()
	keyPath, recipient := genAgeKey(t, dir, "default.key")

	dotenvCipher := filepath.Join(dir, "src.sops.env")
	binaryCipher := filepath.Join(dir, "src.sops.bin")
	sopsEncrypt(t, dir, recipient, "dotenv", buildDotenvPlaintext(), dotenvCipher)
	sopsEncrypt(t, dir, recipient, "binary", binaryFixture, binaryCipher)

	be := NewSOPSAge(map[string]string{"default": keyPath})
	ctx := context.Background()

	dotenvSrc := Sealed{Name: "src", Path: dotenvCipher, Format: FormatDotenv, KeyRef: "default"}
	binarySrc := Sealed{Name: "src", Path: binaryCipher, Format: FormatBinary, KeyRef: "default"}

	// Buffer path: Keys, then Value byte-compare per key.
	t.Run("dotenv buffer path", func(t *testing.T) {
		op, err := be.Open(ctx, dotenvSrc)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer op.Close()

		keys, err := op.Keys()
		if err != nil {
			t.Fatalf("Keys: %v", err)
		}
		got := map[string]bool{}
		for _, k := range keys {
			got[k] = true
		}
		for _, kv := range dotenvFixture {
			if !got[kv.key] {
				t.Errorf("Keys missing %q (got %v)", kv.key, keys)
			}
		}

		for _, kv := range dotenvFixture {
			v, err := op.Value(kv.key)
			if err != nil {
				t.Fatalf("Value(%q): %v", kv.key, err)
			}
			if !bytes.Equal(v, []byte(kv.value)) {
				t.Errorf("Value(%q) = %q, want %q", kv.key, v, kv.value)
			}
		}
	})

	// Stream path (stand-in fd): WriteValue into a buffer, byte-compare.
	t.Run("dotenv stream path", func(t *testing.T) {
		op, err := be.Open(ctx, dotenvSrc)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer op.Close()
		for _, kv := range dotenvFixture {
			var sink bytes.Buffer
			n, err := op.WriteValue(&sink, kv.key)
			if err != nil {
				t.Fatalf("WriteValue(%q): %v", kv.key, err)
			}
			if int(n) != len(kv.value) || !bytes.Equal(sink.Bytes(), []byte(kv.value)) {
				t.Errorf("WriteValue(%q) = %q (n=%d), want %q", kv.key, sink.Bytes(), n, kv.value)
			}
		}
	})

	// Binary buffer path and stream path.
	t.Run("binary paths", func(t *testing.T) {
		op, err := be.Open(ctx, binarySrc)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer op.Close()

		p, err := op.Payload()
		if err != nil {
			t.Fatalf("Payload: %v", err)
		}
		if !bytes.Equal(p, binaryFixture) {
			t.Errorf("Payload = %v, want %v", p, binaryFixture)
		}

		var sink bytes.Buffer
		n, err := op.WritePayload(&sink)
		if err != nil {
			t.Fatalf("WritePayload: %v", err)
		}
		if int(n) != len(binaryFixture) || !bytes.Equal(sink.Bytes(), binaryFixture) {
			t.Errorf("WritePayload = %v (n=%d), want %v", sink.Bytes(), n, binaryFixture)
		}
	})

	// Format guards.
	t.Run("format guards", func(t *testing.T) {
		dop, _ := be.Open(ctx, dotenvSrc)
		defer dop.Close()
		if _, err := dop.Payload(); !errors.Is(err, ErrWrongFormat) {
			t.Errorf("Payload on dotenv = %v, want ErrWrongFormat", err)
		}
		bop, _ := be.Open(ctx, binarySrc)
		defer bop.Close()
		if _, err := bop.Keys(); !errors.Is(err, ErrWrongFormat) {
			t.Errorf("Keys on binary = %v, want ErrWrongFormat", err)
		}
	})
}

func TestSOPSAgeFailurePaths(t *testing.T) {
	requireTool(t, "sops")
	requireTool(t, "age-keygen")

	dir := t.TempDir()
	keyPath, recipient := genAgeKey(t, dir, "default.key")
	wrongKeyPath, _ := genAgeKey(t, dir, "wrong.key")

	dotenvCipher := filepath.Join(dir, "src.sops.env")
	sopsEncrypt(t, dir, recipient, "dotenv", buildDotenvPlaintext(), dotenvCipher)

	ctx := context.Background()
	dotenvSrc := Sealed{Name: "src", Path: dotenvCipher, Format: FormatDotenv, KeyRef: "default"}

	// Missing KEY is an error, never an empty value, and does not leak.
	t.Run("missing key", func(t *testing.T) {
		be := NewSOPSAge(map[string]string{"default": keyPath})
		op, err := be.Open(ctx, dotenvSrc)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer op.Close()
		_, err = op.Value("NOT_A_KEY")
		if !errors.Is(err, ErrNoSuchKey) {
			t.Fatalf("Value(missing) = %v, want ErrNoSuchKey", err)
		}
		assertNoLeak(t, "missing-key error", err.Error())
	})

	// Wrong age key: sops exits nonzero, ErrDecrypt, no value in the error.
	t.Run("wrong age key", func(t *testing.T) {
		be := NewSOPSAge(map[string]string{"default": wrongKeyPath})
		op, err := be.Open(ctx, dotenvSrc)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer op.Close()
		_, err = op.Value("SIMPLE")
		if !errors.Is(err, ErrDecrypt) {
			t.Fatalf("Value with wrong key = %v, want ErrDecrypt", err)
		}
		assertNoLeak(t, "wrong-key error", err.Error())
	})

	// Missing ciphertext file: ErrSourceMissing at Open.
	t.Run("missing source file", func(t *testing.T) {
		be := NewSOPSAge(map[string]string{"default": keyPath})
		missing := Sealed{Name: "gone", Path: filepath.Join(dir, "nope.sops.env"), Format: FormatDotenv, KeyRef: "default"}
		_, err := be.Open(ctx, missing)
		if !errors.Is(err, ErrSourceMissing) {
			t.Fatalf("Open(missing) = %v, want ErrSourceMissing", err)
		}
		assertNoLeak(t, "missing-source error", err.Error())
	})

	// Unknown age key name: ErrUnknownAgeKey at Open.
	t.Run("unknown age key name", func(t *testing.T) {
		be := NewSOPSAge(map[string]string{"default": keyPath})
		bad := Sealed{Name: "src", Path: dotenvCipher, Format: FormatDotenv, KeyRef: "nonexistent"}
		_, err := be.Open(ctx, bad)
		if !errors.Is(err, ErrUnknownAgeKey) {
			t.Fatalf("Open(unknown key) = %v, want ErrUnknownAgeKey", err)
		}
	})
}
