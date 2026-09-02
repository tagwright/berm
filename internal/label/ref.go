// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package label

import (
	"regexp"
	"strings"
)

// keyPattern is the dotenv-env-var shape: uppercase letters, digits, and
// underscores, not leading with a digit.
var keyPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// sourcePattern is the identifier shape: lowercase letters, digits, and dashes,
// not leading or trailing with a dash. The two classes never overlap with
// keyPattern (keys are uppercase, sources lowercase), so the single "/"
// separator in a ref is unambiguous and no escaping is ever needed.
var sourcePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// isKey reports whether s is a valid dotenv key name.
func isKey(s string) bool { return keyPattern.MatchString(s) }

// isSource reports whether s is a valid source name.
func isSource(s string) bool { return sourcePattern.MatchString(s) }

// ParseRef parses one secret reference against the grammar:
//
//	ref := KEY | source "/" KEY | source
//
// A KEY alone is a RefKey (read that key from the container's default source).
// A source/KEY is a RefSourceKey (a named key from a named source). A bare
// source is a RefSource (the whole payload of a source). A syntactically
// invalid ref returns a ClassMalformed error. Format validation (a bare source
// ref is valid only for a binary source, a source/KEY ref only for a dotenv
// source) is a resolve-time concern, because format is a property of the source
// in berm.yml and is never restated in a label.
func ParseRef(s string) (Ref, error) {
	if s == "" {
		return Ref{}, newError(ClassMalformed, map[string]string{"ref": s}, "empty secret reference")
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		// A source/KEY ref. Exactly one separator, both halves well-formed.
		if strings.IndexByte(s[i+1:], '/') >= 0 {
			return Ref{}, newError(ClassMalformed, map[string]string{"ref": s}, "secret reference has more than one %q separator", "/")
		}
		source, key := s[:i], s[i+1:]
		if !isSource(source) || !isKey(key) {
			return Ref{}, newError(ClassMalformed, map[string]string{"ref": s}, "malformed source/KEY reference")
		}
		return Ref{Kind: RefSourceKey, Source: source, Key: key}, nil
	}
	switch {
	case isKey(s):
		return Ref{Kind: RefKey, Key: s}, nil
	case isSource(s):
		return Ref{Kind: RefSource, Source: s}, nil
	default:
		return Ref{}, newError(ClassMalformed, map[string]string{"ref": s}, "malformed secret reference")
	}
}
