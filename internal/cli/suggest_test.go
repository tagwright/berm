// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package cli

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tagwright/berm/internal/config"
)

// suggestSecrets is the known plaintext encrypted into the fixture. suggest must
// print none of these values: it reads only the cleartext KEY names.
var suggestSecrets = []struct{ key, value string }{
	{"DB_PASSWORD", "supersecret-db-1234"},
	{"API_KEY", "api-key-abcd-9999"},
	{"SMTP_PASSWORD", "smtp-pass-zzzz"},
	{"REDIS_URL", "redis://user:redispw-7777@host:6379"},
}

func suggestSecretValues() []string {
	out := make([]string, 0, len(suggestSecrets))
	for _, s := range suggestSecrets {
		out = append(out, s.value)
	}
	return out
}

func TestSuggestReadsKeyNamesNeverValues(t *testing.T) {
	requireTool(t, "sops")
	requireTool(t, "age-keygen")

	dir := t.TempDir()
	_, recipient := genAgeKey(t, dir, "default.key")

	var plain bytes.Buffer
	for _, s := range suggestSecrets {
		plain.WriteString(s.key)
		plain.WriteByte('=')
		plain.WriteString(s.value)
		plain.WriteByte('\n')
	}
	cipher := filepath.Join(dir, "webapp.sops.env")
	sopsEncrypt(t, dir, recipient, "dotenv", plain.Bytes(), cipher)

	// A sabotage "sops" on PATH that records its own invocation. suggest must
	// never run it: it parses the encrypted file's cleartext keys directly.
	marker := filepath.Join(dir, "sops-invoked.marker")
	installSabotageSops(t, dir, marker)

	var out bytes.Buffer
	if err := Suggest(&out, SuggestInput{Service: "webapp", File: cipher}); err != nil {
		t.Fatalf("suggest: %v", err)
	}
	got := out.String()

	// No sops subprocess ran.
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("suggest invoked sops (marker %s exists): it must parse cleartext keys directly", marker)
	}

	// The no-value invariant: not one plaintext value appears in the output.
	assertNoValue(t, "suggest output", got, suggestSecretValues()...)

	// The right key names, as file deliveries (the secure default), lead.
	for _, s := range suggestSecrets {
		wantLabel := "berm.file." + strings.ToLower(s.key) + ".from: \"" + s.key + "\""
		if !strings.Contains(got, wantLabel) {
			t.Errorf("output missing file label %q\n---\n%s", wantLabel, got)
		}
	}

	// The env-shaped alternative is present but commented and named as exposed.
	for _, want := range []string{
		`# berm.env: "all"`,
		`# berm.env.acknowledge: "true"`,
		"/proc/<pid>/environ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing env-alternative marker %q", want)
		}
	}

	// The berm.yml sources stanza names the service, file, format, and owner.
	for _, want := range []string{
		"sources:",
		"      webapp:",
		"        file: webapp.sops.env",
		"        format: dotenv",
		"        owner: webapp",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing stanza line %q\n---\n%s", want, got)
		}
	}
}

// TestSuggestLocatesViaBermYaml proves suggest can find the file from berm.yml
// (source entry, resolved under BERM_SOURCES_ROOT) when no --file is given, and
// carries the source's binary format through to a whole-payload suggestion.
func TestSuggestBinarySourceFromConfig(t *testing.T) {
	requireTool(t, "sops")
	requireTool(t, "age-keygen")

	dir := t.TempDir()
	_, recipient := genAgeKey(t, dir, "default.key")

	payload := []byte("this-is-a-whole-binary-secret-payload")
	cipher := filepath.Join(dir, "webapp-tls.sops.bin")
	sopsEncrypt(t, dir, recipient, "binary", payload, cipher)

	cfg := &config.Config{
		Sources: map[string]config.Source{
			"webapp-tls": {File: "webapp-tls.sops.bin", Format: "binary"},
		},
	}
	cfg.Globals.SourcesRoot = dir

	var out bytes.Buffer
	if err := Suggest(&out, SuggestInput{Service: "webapp-tls", Config: cfg}); err != nil {
		t.Fatalf("suggest: %v", err)
	}
	got := out.String()

	assertNoValue(t, "suggest binary output", got, string(payload))
	for _, want := range []string{
		`berm.file.webapp-tls.from: "webapp-tls"`,
		"        format: binary",
		"        owner: webapp-tls",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("binary suggest output missing %q\n---\n%s", want, got)
		}
	}
	// A binary source has no keys, so no env alternative is offered.
	if strings.Contains(got, "berm.env") {
		t.Errorf("binary suggest must not offer an env alternative:\n%s", got)
	}
}

// installSabotageSops writes an executable "sops" into dir and prepends dir to
// PATH for the test. If anything execs sops, the script creates marker (holding
// the plaintext values), so a present marker proves an invocation and a decrypt
// attempt. suggest must never trigger it.
func installSabotageSops(t *testing.T, dir, marker string) {
	t.Helper()
	script := "#!/bin/sh\nprintf 'invoked' > " + marker + "\n"
	p := filepath.Join(dir, "sops")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("write sabotage sops: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// --- sops/age test helpers (local to package cli) ---------------------------

func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("suggest test needs %q on PATH: %v", name, err)
	}
}

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
