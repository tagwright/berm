// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/config"
)

// SuggestInput is everything Suggest needs to propose labels for one service:
// the service name, an optional explicit ciphertext file, an optional explicit
// format, and the optional loaded berm.yml it consults to locate the file and
// format when they are not given. Nothing here is a secret value.
type SuggestInput struct {
	// Service is the compose service to suggest labels for.
	Service string

	// File is the explicit path to the service's existing sops-encrypted secret
	// file. Empty falls back to berm.yml, then to the documented convention.
	File string

	// Format is an explicit "dotenv" or "binary". Empty is inferred from
	// berm.yml, then from the file extension.
	Format string

	// Config is the loaded berm.yml, consulted to locate the file (the source's
	// file entry, resolved under BERM_SOURCES_ROOT) and its format when the
	// flags omit them. It may be nil.
	Config *config.Config
}

// Suggest is the migration on-ramp. Given a service and its existing hand-rolled
// sops-encrypted secret file, it reads only the CLEARTEXT KEY NAMES from that
// file (sops keeps dotenv keys in cleartext and encrypts only the values as
// ENC[...]) and prints ready-to-paste berm labels and the matching berm.yml
// sources stanza. File delivery is the secure default and is led with; the
// env-shaped alternative is emitted commented-out and annotated as the exposed
// path. It PROPOSES: the operator reviews and pastes, and nothing is auto-
// discovered or auto-written. It NEVER runs sops -d, never decrypts, and never
// prints a value: it parses the encrypted file's cleartext keys directly.
func Suggest(w io.Writer, in SuggestInput) error {
	if in.Service == "" {
		return fmt.Errorf("suggest: a service name is required")
	}

	file, format, err := locateSource(in)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("suggest: read source file %s: %w", file, err)
	}

	fmt.Fprintf(w, "berm suggest: service %q\n", in.Service)

	stanzaFile := filepath.Base(file)
	switch format {
	case backend.FormatBinary:
		suggestBinary(w, in.Service, file, stanzaFile)
	default:
		keys, kerr := dotenvSecretKeys(data)
		if kerr != nil {
			return fmt.Errorf("suggest: parse %s: %w", file, kerr)
		}
		if len(keys) == 0 {
			return fmt.Errorf("suggest: %s has no secret keys (only sops metadata): is it a sops dotenv file?", file)
		}
		suggestDotenv(w, in.Service, file, stanzaFile, keys)
	}

	fmt.Fprintln(w, "\nberm proposes, you commit: review the above and paste what you want.")
	fmt.Fprintln(w, "No secret value was read or printed, and sops was never invoked to decrypt.")
	return nil
}

// suggestDotenv prints the file-delivery labels (the secure default, led with)
// and the commented env alternative, then the berm.yml sources stanza.
func suggestDotenv(w io.Writer, service, file, stanzaFile string, keys []string) {
	fmt.Fprintf(w, "source file: %s (sops dotenv, %d secret key(s); values not read, not decrypted)\n", file, len(keys))

	fmt.Fprintln(w, "\nPaste into the service's compose labels (file delivery is the secure default):")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    labels:")
	fmt.Fprintln(w, `      berm.enable: "true"`)
	for _, k := range keys {
		fmt.Fprintf(w, "      berm.file.%s.from: %q\n", strings.ToLower(k), k)
	}
	fmt.Fprintln(w, "      # Env-shaped alternative. ENV IS THE EXPOSED PATH:")
	fmt.Fprintf(w, "      # %s.\n", envExposureNote)
	fmt.Fprintln(w, "      # Uncomment only if this app cannot read its secrets from files,")
	fmt.Fprintln(w, "      # and keep the acknowledgment, which affirms the exposure every time:")
	fmt.Fprintln(w, `      # berm.delivery: "client"`)
	fmt.Fprintln(w, `      # berm.env: "all"`)
	fmt.Fprintln(w, `      # berm.env.acknowledge: "true"`)

	printSourcesStanza(w, service, stanzaFile, "dotenv")
}

// suggestBinary prints the whole-payload file delivery for a binary source and
// its sources stanza. A binary source has one payload and no keys, so there is
// no env-shaped alternative.
func suggestBinary(w io.Writer, service, file, stanzaFile string) {
	fmt.Fprintf(w, "source file: %s (sops binary, one whole payload; not read, not decrypted)\n", file)

	fmt.Fprintln(w, "\nPaste into the service's compose labels (a binary source is delivered whole to a file):")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    labels:")
	fmt.Fprintln(w, `      berm.enable: "true"`)
	fmt.Fprintf(w, "      berm.file.%s.from: %q   # bare source ref delivers the whole binary payload\n",
		strings.ToLower(service), service)

	printSourcesStanza(w, service, stanzaFile, "binary")
}

// printSourcesStanza prints the berm.yml sources entry for the service: its
// name, file, format, and owner defaulting to the service. Nothing in it is a
// secret value.
func printSourcesStanza(w io.Writer, service, stanzaFile, format string) {
	fmt.Fprintln(w, "\nPaste into berm.yml (file: resolves under BERM_SOURCES_ROOT):")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    sources:")
	fmt.Fprintf(w, "      %s:\n", service)
	fmt.Fprintf(w, "        file: %s\n", stanzaFile)
	fmt.Fprintf(w, "        format: %s\n", format)
	fmt.Fprintf(w, "        owner: %s\n", service)
}

// locateSource resolves the ciphertext file path and format for the service.
// The file comes from the explicit flag, else the berm.yml source entry
// (resolved under BERM_SOURCES_ROOT), else the documented convention
// <BERM_SOURCES_ROOT>/<service>.sops.env. The format comes from the explicit
// flag, else the berm.yml source format, else the file extension.
func locateSource(in SuggestInput) (file string, format backend.SourceFormat, err error) {
	var cfgFormat string
	switch {
	case in.File != "":
		file = in.File
	case in.Config != nil && sourceHasFile(in.Config, in.Service):
		src := in.Config.Sources[in.Service]
		file = resolveUnderRoot(in.Config, src.File)
		cfgFormat = src.Format
	default:
		root := ""
		if in.Config != nil {
			root = in.Config.Globals.SourcesRoot
		}
		if root == "" {
			return "", "", fmt.Errorf("suggest: no --file given, service %q is not in berm.yml, and BERM_SOURCES_ROOT is unset, so the source file cannot be located", in.Service)
		}
		file = filepath.Join(root, in.Service+".sops.env")
	}

	format = pickFormat(in.Format, cfgFormat, file)
	if !format.Valid() {
		return "", "", fmt.Errorf("suggest: unrecognized format %q, want dotenv or binary", format)
	}
	return file, format, nil
}

// pickFormat resolves the source format from the explicit flag, else the
// berm.yml format, else the file extension (a .bin extension is binary,
// everything else is the dotenv default).
func pickFormat(flag, cfgFormat, file string) backend.SourceFormat {
	if flag != "" {
		return backend.SourceFormat(flag)
	}
	if cfgFormat != "" {
		return backend.SourceFormat(cfgFormat)
	}
	if strings.HasSuffix(file, ".bin") {
		return backend.FormatBinary
	}
	return backend.FormatDotenv
}

// sourceHasFile reports whether berm.yml defines the service as a source with a
// file entry.
func sourceHasFile(cfg *config.Config, service string) bool {
	src, ok := cfg.Sources[service]
	return ok && src.File != ""
}

// resolveUnderRoot resolves a berm.yml file entry the way the daemon does:
// absolute as-is, relative under BERM_SOURCES_ROOT.
func resolveUnderRoot(cfg *config.Config, file string) string {
	if filepath.IsAbs(file) || cfg.Globals.SourcesRoot == "" {
		return file
	}
	return filepath.Join(cfg.Globals.SourcesRoot, file)
}

// dotenvSecretKeys lists the cleartext secret key names in a sops-encrypted
// dotenv file, in file order, de-duplicated. sops writes one KEY=ENC[...] line
// per secret with the KEY in cleartext and the value encrypted, plus a block of
// sops_* metadata lines (sops_version, sops_mac, sops_age__..., and so on). This
// keeps the secret keys and drops the lowercase sops_ metadata. It reads NAMES
// only: it never parses, decodes, or emits a value, and it never runs sops.
func dotenvSecretKeys(data []byte) ([]string, error) {
	var keys []string
	seen := map[string]bool{}
	for _, raw := range bytes.Split(data, []byte{'\n'}) {
		line := bytes.TrimRight(raw, "\r")
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		eq := bytes.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("malformed dotenv line without '='")
		}
		key := string(line[:eq])
		if key == "" {
			return nil, fmt.Errorf("malformed dotenv line with empty key")
		}
		// Drop sops's own metadata keys, which use a lowercase sops_ prefix.
		// A real secret key is conventionally uppercase, so an uppercase
		// SOPS_* key (if any) is kept as a genuine secret name.
		if strings.HasPrefix(key, "sops_") {
			continue
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		keys = append(keys, key)
	}
	return keys, nil
}
