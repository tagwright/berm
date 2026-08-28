// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package backend

import (
	"bytes"
	"fmt"
)

// dotenv parsing matched to what the sops dotenv store emits, not to a generic
// shell dotenv. sops writes one "KEY=VALUE" line per entry, splits on the FIRST
// '=' only, treats the remainder as the value verbatim with no quote stripping,
// keeps blank lines out, and stores a line beginning with '#' as a comment. A
// value therefore round-trips byte for byte, quotes and spaces and embedded '='
// included, which is exactly the property the buffer path must preserve.
//
// Every function here operates on a byte slice that is backed by locked memory
// (a memguard buffer's bytes). Key NAMES are lifted to strings, which is safe
// because a key name is not a secret and the grammar forbids a value from
// living where a name does. Values are never turned into strings: they are
// returned as sub-slices of the locked backing, for the caller to copy into its
// own locked buffer or stream to a destination before the backing is destroyed.

// dotenvLineKey splits one already-trimmed, non-comment, non-blank line into its
// key name and its value sub-slice. ok is false when the line has no '=', which
// the caller treats as malformed.
func dotenvLineKey(line []byte) (key string, value []byte, ok bool) {
	eq := bytes.IndexByte(line, '=')
	if eq < 0 {
		return "", nil, false
	}
	return string(line[:eq]), line[eq+1:], true
}

// isBlankOrComment reports whether a raw line contributes no key. sops emits
// bare "KEY=VALUE" lines with no leading whitespace, but a blank line or a
// comment line is tolerated on the way in and skipped on the way out.
func isBlankOrComment(line []byte) bool {
	if len(line) == 0 {
		return true
	}
	return line[0] == '#'
}

// dotenvKeys lists the key names in data, in file order. It exposes names only
// and never a value. A non-blank, non-comment line without an '=' is malformed
// and surfaces ErrMalformed, named by source at the call site.
func dotenvKeys(data []byte) ([]string, error) {
	var keys []string
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if isBlankOrComment(line) {
			continue
		}
		key, _, ok := dotenvLineKey(line)
		if !ok {
			return nil, ErrMalformed
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// dotenvFind returns the value sub-slice for key, verbatim, as a view into data.
// found is false when no line names key. A malformed line surfaces ErrMalformed
// so a corrupt source is a loud error, never a silently absent secret. The
// returned slice aliases data, so the caller must copy it into its own locked
// buffer (or write it out) before the backing buffer is destroyed.
func dotenvFind(data []byte, key string) (value []byte, found bool, err error) {
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if isBlankOrComment(line) {
			continue
		}
		k, v, ok := dotenvLineKey(line)
		if !ok {
			return nil, false, ErrMalformed
		}
		if k == key {
			return v, true, nil
		}
	}
	return nil, false, nil
}

// wrapSource decorates a bare typed error with the source name (never a value)
// so the resolver's log and the beacon digest can name what failed without ever
// naming what it held.
func wrapSource(err error, sourceName string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w (source %q)", err, sourceName)
}
