// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package label

import (
	"regexp"
	"sort"
	"strings"

	"github.com/tagwright/berm/internal/delivery"
)

// ownerPattern is uid[:gid], numeric only. No names, so a delivered file's
// ownership can never depend on the daemon's passwd database.
var ownerPattern = regexp.MustCompile(`^[0-9]+(:[0-9]+)?$`)

// modePattern is a three or four digit octal string, e.g. "0400" or "440".
var modePattern = regexp.MustCompile(`^[0-7]{3,4}$`)

// fileAttrs is the closed set of berm.file.<name>.<attr> attributes.
var fileAttrs = map[string]bool{"from": true, "path": true, "owner": true, "mode": true}

// Parse turns one container's labels into a ContainerSpec, applying the two
// doorways, one grammar rule: the reader holds the recognized prefixes berm.
// and tagwright.secret., strips whichever matches, and parses one canonical
// suffix grammar. The same suffix under both prefixes with different values is a
// ClassCrossPrefixConflict error (same value is harmless). An unknown suffix is
// a ClassUnknownSuffix error. Any berm.env* label without berm.env.acknowledge
// is a hard ClassEnvNoAck error. berm.rotate is ClassRotateReserved.
//
// Parse validates only what a label carries on its own: prefix conflicts,
// unknown suffixes, value syntax, ref syntax, the env acknowledgment, and the
// reserved rotate label. It does not consult berm.yml. Source existence, format
// versus ref shape, owner and grant scoping, the env delivery mechanism gate,
// and the all sentinel's owned-source rule are resolve-time concerns, since
// they need the loaded config. A disabled container (berm.enable absent or not
// true) parses to an inert ContainerSpec with Enabled false and no error: it is
// simply skipped, never alerted.
func Parse(labels map[string]string) (ContainerSpec, error) {
	merged, err := mergeDoorways(labels)
	if err != nil {
		return ContainerSpec{}, err
	}

	spec := ContainerSpec{}
	if merged["enable"] != "true" {
		// Absent or false is identical: the container is inert.
		return spec, nil
	}
	spec.Enabled = true

	files := map[string]*FileDelivery{}
	var envList []EnvDelivery
	var renameEnv []EnvDelivery
	hasEnvLabel := false

	// Iterate suffixes in a stable order so a container with two independent
	// mistakes fails on the same one every run.
	suffixes := make([]string, 0, len(merged))
	for s := range merged {
		suffixes = append(suffixes, s)
	}
	sort.Strings(suffixes)

	for _, suffix := range suffixes {
		val := merged[suffix]
		switch {
		case suffix == "enable":
			// Already consumed by the gate above.
		case suffix == "name":
			spec.Name = val
		case suffix == "source":
			if !isSource(val) {
				return ContainerSpec{}, newError(ClassMalformed, map[string]string{"berm.source": val}, "berm.source is not a valid source name")
			}
			spec.Source = val
		case suffix == "delivery":
			m := delivery.Mechanism(val)
			if !m.Valid() {
				return ContainerSpec{}, newError(ClassMalformed, map[string]string{"berm.delivery": val}, "berm.delivery must be one of client, hook, volume")
			}
			spec.Delivery = m
		case suffix == "volume":
			spec.Volume = val
		case suffix == "owner":
			if !ownerPattern.MatchString(val) {
				return ContainerSpec{}, newError(ClassMalformed, map[string]string{"berm.owner": val}, "berm.owner must be numeric uid[:gid]")
			}
			spec.Owner = val
		case suffix == "mode":
			if !modePattern.MatchString(val) {
				return ContainerSpec{}, newError(ClassMalformed, map[string]string{"berm.mode": val}, "berm.mode must be an octal string")
			}
			spec.Mode = val
		case suffix == "dotenv":
			if !strings.HasPrefix(val, "/") {
				return ContainerSpec{}, newError(ClassMalformed, map[string]string{"berm.dotenv": val}, "berm.dotenv must be an absolute path")
			}
			spec.Dotenv = val
		case suffix == "envdir":
			if !strings.HasPrefix(val, "/") {
				return ContainerSpec{}, newError(ClassMalformed, map[string]string{"berm.envdir": val}, "berm.envdir must be an absolute path")
			}
			spec.Envdir = val
		case suffix == "rotate":
			return ContainerSpec{}, newError(ClassRotateReserved, map[string]string{"label": "berm.rotate"}, "berm.rotate is reserved and rejected in v1")
		case suffix == "env":
			hasEnvLabel = true
			ev, err := parseEnvList(val)
			if err != nil {
				return ContainerSpec{}, err
			}
			envList = ev
		case suffix == "env.acknowledge":
			spec.EnvAck = val == "true"
		case strings.HasPrefix(suffix, "env."):
			// env.<VAR>: one ref delivered as env var <VAR>. The rename and
			// cross-source form.
			hasEnvLabel = true
			varName := strings.TrimPrefix(suffix, "env.")
			ed, err := parseEnvVar(varName, val)
			if err != nil {
				return ContainerSpec{}, err
			}
			renameEnv = append(renameEnv, ed)
		case strings.HasPrefix(suffix, "file."):
			if err := parseFile(files, strings.TrimPrefix(suffix, "file."), val); err != nil {
				return ContainerSpec{}, err
			}
		default:
			return ContainerSpec{}, newError(ClassUnknownSuffix, map[string]string{"suffix": suffix}, "unknown berm label suffix %q", suffix)
		}
	}

	// Env is double-gated: any berm.env* label requires berm.env.acknowledge on
	// the same container. Without it the whole container is a hard, sticky
	// error, not a warning.
	if hasEnvLabel && !spec.EnvAck {
		return ContainerSpec{}, newError(ClassEnvNoAck, nil, "berm.env* labels require berm.env.acknowledge=true on the same container")
	}

	// Assemble env deliveries: the csv list first, then the rename form sorted by
	// target var, so a resolved plan is deterministic.
	sort.Slice(renameEnv, func(i, j int) bool { return renameEnv[i].Var < renameEnv[j].Var })
	spec.Env = append(envList, renameEnv...)

	// Assemble file deliveries sorted by name.
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		spec.Files = append(spec.Files, *files[n])
	}

	return spec, nil
}

// mergeDoorways strips the two recognized prefixes and merges the results into
// one suffix map. The same suffix under both prefixes with different values is a
// ClassCrossPrefixConflict error. The same value under both is harmless and
// yields a single entry. A label under neither prefix is ignored.
func mergeDoorways(labels map[string]string) (map[string]string, error) {
	merged := map[string]string{}
	for k, v := range labels {
		var suffix string
		switch {
		case strings.HasPrefix(k, PrimaryPrefix):
			suffix = strings.TrimPrefix(k, PrimaryPrefix)
		case strings.HasPrefix(k, AliasPrefix):
			suffix = strings.TrimPrefix(k, AliasPrefix)
		default:
			continue
		}
		if prev, ok := merged[suffix]; ok && prev != v {
			return nil, newError(ClassCrossPrefixConflict, map[string]string{"suffix": suffix},
				"suffix %q has different values under the primary and alias prefixes", suffix)
		}
		merged[suffix] = v
	}
	return merged, nil
}

// parseEnvList parses the berm.env value: either the single sentinel all or a
// csv of refs, each delivered as an env var named for the ref's key. A bare
// source ref (a binary whole payload) names no key and is a ClassWrongRefShape
// error, since an env var needs a name.
func parseEnvList(val string) ([]EnvDelivery, error) {
	if val == "all" {
		return []EnvDelivery{{All: true}}, nil
	}
	var out []EnvDelivery
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ref, err := ParseRef(part)
		if err != nil {
			return nil, err
		}
		if ref.Kind == RefSource {
			return nil, newError(ClassWrongRefShape, map[string]string{"ref": part},
				"env ref %q names a whole source with no key, but an env var needs a key", part)
		}
		out = append(out, EnvDelivery{Var: ref.Key, Ref: ref})
	}
	return out, nil
}

// parseEnvVar parses a berm.env.<VAR> rename delivery. The ref must name a key,
// since a whole binary payload cannot become one env var.
func parseEnvVar(varName, val string) (EnvDelivery, error) {
	if varName == "" {
		return EnvDelivery{}, newError(ClassUnknownSuffix, map[string]string{"suffix": "env."}, "berm.env. has an empty variable name")
	}
	ref, err := ParseRef(val)
	if err != nil {
		return EnvDelivery{}, err
	}
	if ref.Kind == RefSource {
		return EnvDelivery{}, newError(ClassWrongRefShape, map[string]string{"ref": val, "var": varName},
			"env ref %q names a whole source with no key, but an env var needs a key", val)
	}
	return EnvDelivery{Var: varName, Ref: ref}, nil
}

// parseFile parses one berm.file.<name>.<attr> label into the accumulating file
// map. rest is the suffix past "file.". The attribute is the final segment and
// the name is everything before it, so a delivery name may itself contain dots.
func parseFile(files map[string]*FileDelivery, rest, val string) error {
	i := strings.LastIndexByte(rest, '.')
	if i < 0 {
		return newError(ClassUnknownSuffix, map[string]string{"suffix": "file." + rest}, "berm.file.%s has no attribute", rest)
	}
	name, attr := rest[:i], rest[i+1:]
	if name == "" || strings.Contains(name, "/") {
		return newError(ClassUnknownSuffix, map[string]string{"suffix": "file." + rest}, "berm.file delivery name %q is invalid", name)
	}
	if !fileAttrs[attr] {
		return newError(ClassUnknownSuffix, map[string]string{"suffix": "file." + rest},
			"unknown berm.file attribute %q (want from, path, owner, or mode)", attr)
	}

	fd := files[name]
	if fd == nil {
		fd = &FileDelivery{Name: name}
		files[name] = fd
	}
	switch attr {
	case "from":
		ref, err := ParseRef(val)
		if err != nil {
			return err
		}
		fd.From = ref
	case "path":
		if !strings.HasPrefix(val, "/") {
			return newError(ClassMalformed, map[string]string{"berm.file." + name + ".path": val}, "berm.file.%s.path must be an absolute path", name)
		}
		fd.Path = val
	case "owner":
		if !ownerPattern.MatchString(val) {
			return newError(ClassMalformed, map[string]string{"berm.file." + name + ".owner": val}, "berm.file.%s.owner must be numeric uid[:gid]", name)
		}
		fd.Owner = val
	case "mode":
		if !modePattern.MatchString(val) {
			return newError(ClassMalformed, map[string]string{"berm.file." + name + ".mode": val}, "berm.file.%s.mode must be an octal string", name)
		}
		fd.Mode = val
	}
	return nil
}
