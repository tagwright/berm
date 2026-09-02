// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package label

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Class classifies a berm validation failure so the caller can tell a sticky
// secrets-affecting error from a transient one, and can route each class to the
// beacon-backed alert Sink with the right severity. Every classified failure is
// skip-and-alert: it skips exactly one container and never breaks injection for
// the rest of the fleet.
type Class int

const (
	// ClassUnknownSuffix is a berm.* / tagwright.secret.* suffix the grammar
	// does not recognize (a mistyped berm.fille.db.path). Airlock hardening: a
	// silently-absent secret is a production outage found at the worst time, so
	// an unknown suffix fails loudly.
	ClassUnknownSuffix Class = iota

	// ClassCrossPrefixConflict is the same suffix present under both the primary
	// and the alias prefix with different values. The ballast conflict rule,
	// inherited verbatim: same value is harmless, different values is an error.
	ClassCrossPrefixConflict

	// ClassWrongRefShape is a ref whose shape does not match its source's
	// format: a bare source ref against a dotenv source, a source/KEY ref
	// against a binary source, a bare KEY read from a binary default source, or
	// an env ref that names no key.
	ClassWrongRefShape

	// ClassMissingSource is a reference to a source not present in berm.yml,
	// whether by the default (service name) or explicitly. Sticky: a renamed or
	// deleted source must not scroll out of the digest.
	ClassMissingSource

	// ClassUngrantedRef is a cross-service reference the source's owner and
	// access list do not permit. Sticky: an ungranted read is a security-shaped
	// mistake that must stay visible until fixed.
	ClassUngrantedRef

	// ClassEnvNoAck is any berm.env* label without berm.env.acknowledge=true on
	// the same container. Hard (not a warning) and sticky: env is the exposed
	// path and the acknowledgment is the second gate.
	ClassEnvNoAck

	// ClassEnvWrongMechanism is an env delivery on a mechanism that cannot
	// control the process environment (hook or volume). Env is client-only and a
	// silent no-op would be worse than an error.
	ClassEnvWrongMechanism

	// ClassAllCrossService is the berm.env=all sentinel used against a source the
	// container does not own. all is legal only on the container's own owned
	// default source, so no single label ever blanket-grants another service's
	// whole payload into the environment.
	ClassAllCrossService

	// ClassRotateReserved is the reserved berm.rotate label, rejected in v1 so a
	// future additive auto-recreate opt-in can land without a grammar collision.
	ClassRotateReserved

	// ClassMalformed is a syntactically invalid value: a bad delivery enum, a
	// non-numeric owner, a non-octal mode, a relative path, or an unparseable
	// ref.
	ClassMalformed

	// ClassBadConfig is a container whose delivery mechanism cannot be resolved
	// from the label, BERM_DEFAULT_DELIVERY, or berm.yml defaults.
	ClassBadConfig
)

// stickyClasses are the secrets-affecting classes the beacon digest holds until
// fixed. They are the three the grammar names: an ungranted reference, a
// missing source, and an env label without its acknowledgment.
func (c Class) Sticky() bool {
	switch c {
	case ClassMissingSource, ClassUngrantedRef, ClassEnvNoAck:
		return true
	default:
		return false
	}
}

// String is a stable machine-readable token for a class, used in alert fields
// and test assertions. It never contains a secret value.
func (c Class) String() string {
	switch c {
	case ClassUnknownSuffix:
		return "unknown_suffix"
	case ClassCrossPrefixConflict:
		return "cross_prefix_conflict"
	case ClassWrongRefShape:
		return "wrong_ref_shape"
	case ClassMissingSource:
		return "missing_source"
	case ClassUngrantedRef:
		return "ungranted_ref"
	case ClassEnvNoAck:
		return "env_no_acknowledge"
	case ClassEnvWrongMechanism:
		return "env_wrong_mechanism"
	case ClassAllCrossService:
		return "all_cross_service"
	case ClassRotateReserved:
		return "rotate_reserved"
	case ClassMalformed:
		return "malformed"
	case ClassBadConfig:
		return "bad_config"
	default:
		return "unknown"
	}
}

// Error is a classified berm validation failure for one container. It carries a
// class, a human-readable message, and structured name/value fields (a
// container, a source, a ref, a suffix), none of which is ever a secret value.
// It is the single error taxonomy for both label parsing and resolve-time
// scoping, so a caller has one type to switch on.
type Error struct {
	// Class is the failure class, which also decides Sticky.
	Class Class

	// Message is the human-readable reason. It names labels, sources, and refs
	// only, never a secret value.
	Message string

	// Fields are structured name/value pairs for the alert Sink. Never a value.
	Fields map[string]string
}

// Error satisfies the error interface.
func (e *Error) Error() string {
	if len(e.Fields) == 0 {
		return fmt.Sprintf("berm: %s: %s", e.Class, e.Message)
	}
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+e.Fields[k])
	}
	return fmt.Sprintf("berm: %s: %s (%s)", e.Class, e.Message, strings.Join(pairs, " "))
}

// Sticky reports whether this failure is secrets-affecting and must persist in
// the beacon digest until fixed.
func (e *Error) Sticky() bool {
	return e.Class.Sticky()
}

// newError builds a classified Error. fields may be nil.
func newError(class Class, fields map[string]string, format string, args ...any) *Error {
	return &Error{
		Class:   class,
		Message: fmt.Sprintf(format, args...),
		Fields:  fields,
	}
}

// NewError builds a classified Error. It is the exported constructor the
// resolve layer uses so label parsing and resolve-time scoping share one error
// taxonomy. fields may be nil.
func NewError(class Class, fields map[string]string, format string, args ...any) *Error {
	return newError(class, fields, format, args...)
}

// AsError extracts a classified *Error from err, if err is or wraps one. It is
// the caller's bridge from the error interface to the class and stickiness.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
