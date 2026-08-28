// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Package resolve turns a container's parsed berm labels into a validated,
// resolved delivery plan, or a classified skip-and-alert error. It is the layer
// that consults berm.yml: it checks that every referenced source exists, that a
// ref's shape matches its source's format, that an owner or grant permits every
// cross-service read, that the all sentinel is used only on an owned source,
// and that env delivery lands only on the client mechanism. It performs no
// decryption and no delivery. It produces a Plan of targets (a source, a format,
// a key or a whole payload, a path or an env var, an owner, a mode, a
// mechanism, and the env-exposure flag) that the delivery layer consumes.
//
// The security-critical fork is scoping (owner plus grants). A source's owner
// defaults to the source name, and ownership is strict exact-name: a service
// owns a source only when the source's effective owner (explicit owner: else the
// source name) equals the service identity. The owner may read it with no grant,
// and any other service needs the source's access list to name it. See the
// ownership note on serviceOwns for how the worked-example auxiliary source
// (webapp reading webapp-tls, which sets owner: webapp) resolves.
package resolve

import (
	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/delivery"
	"github.com/tagwright/berm/internal/label"
)

// Input is everything Resolve needs for one container: its raw labels, its
// authenticated service identity, its configured user (for the file-owner
// default), the loaded berm.yml, and the effective BERM_DEFAULT_DELIVERY the
// daemon computed per runtime. Nothing here is a secret value.
type Input struct {
	// Labels are the container's raw labels, under either recognized prefix.
	Labels map[string]string

	// ContainerID identifies the container in the resulting Plan and in alerts.
	ContainerID string

	// Service is the container's authenticated service identity, already
	// resolved by the peer authenticator (berm.name override, else the compose
	// service label, else the container name). Replicas share it, and therefore
	// share grants. It is the default source name when berm.source is unset and
	// the identity every grant is checked against.
	Service string

	// ContainerUser is the container's configured user as uid[:gid], used as the
	// file-owner default when neither the file nor berm.owner sets one. Empty
	// falls back to 0:0. The core runtime.Container type does not currently
	// surface the configured user, so the daemon passes it in here.
	ContainerUser string

	// Config is the loaded berm.yml (sources, owners, grants, defaults).
	Config *config.Config

	// DefaultDelivery is the effective BERM_DEFAULT_DELIVERY the daemon computed
	// (Docker client, Podman hook), used when neither berm.delivery nor the
	// berm.yml defaults block sets a mechanism.
	DefaultDelivery delivery.Mechanism
}

// EnvBinding is one resolved env delivery: a var to set from a source key, or
// the all sentinel that expands to every key of an owned source. It names
// targets only and never holds a value.
type EnvBinding struct {
	// Var is the target environment variable name. Empty when All is set.
	Var string

	// Source is the resolved source to read from.
	Source string

	// Key is the dotenv key to read. Empty when All is set.
	Key string

	// All expands to every key of Source, each delivered as an env var named for
	// its key. Legal only on the container's own owned default source.
	All bool
}

// FileBinding is one resolved file delivery, the secure default path. It names
// the source and key or whole payload, the tmpfs target, and the ownership.
type FileBinding struct {
	// Name is the delivery name from berm.file.<name>.*.
	Name string

	// Source is the resolved source to read from.
	Source string

	// Format is the source's declared format.
	Format backend.SourceFormat

	// Whole is true for a binary whole-payload delivery. When false, Key names
	// the dotenv key.
	Whole bool

	// Key is the dotenv key to read. Empty when Whole.
	Key string

	// Path is the absolute, tmpfs-backed destination.
	Path string

	// Owner is the resolved uid[:gid], numeric.
	Owner string

	// Mode is the resolved octal string.
	Mode string

	// PointerVar is the non-secret <KEY>_FILE pointer env var the delivery layer
	// may auto-set to Path, serving the dominant _FILE convention. Its value is a
	// path, not a secret, so it does not trip the env acknowledgment. Empty for a
	// whole-payload delivery, which has no key to name the pointer after. The
	// delivery layer decides whether to emit it (it cannot on a mechanism that
	// does not control the environment).
	PointerVar string
}

// RenderKind is which whole-source render shape a RenderBinding is.
type RenderKind string

const (
	// RenderDotenv renders the whole default source as one dotenv file.
	RenderDotenv RenderKind = "dotenv"

	// RenderEnvdir renders the whole default source key-per-file, the s6-overlay
	// container_environment style.
	RenderEnvdir RenderKind = "envdir"
)

// RenderBinding is one resolved whole-source render. Both shapes are file-mode,
// operate on the default source only, and honor the container-level owner and
// mode defaults.
type RenderBinding struct {
	// Kind is dotenv or envdir.
	Kind RenderKind

	// Source is the default source being rendered.
	Source string

	// Format is the source's declared format, always dotenv for a render.
	Format backend.SourceFormat

	// Path is the absolute target path (a file for dotenv, a directory for
	// envdir).
	Path string

	// Owner is the resolved uid[:gid], numeric.
	Owner string

	// Mode is the resolved octal string.
	Mode string
}

// Plan is the validated, resolved set of deliveries for one enabled container.
// It names targets only and never holds a secret value: the delivery layer
// pulls each value from the backend at execution time. A Plan is produced only
// when validation fully succeeds; any failure returns a classified error
// instead.
type Plan struct {
	// Container is the target container ID.
	Container string

	// Service is the resolved service identity the plan was scoped against.
	Service string

	// Mechanism is the resolved delivery mechanism.
	Mechanism delivery.Mechanism

	// Env are the resolved env deliveries. Non-empty only when Mechanism is
	// client.
	Env []EnvBinding

	// Files are the resolved file deliveries, the secure default path.
	Files []FileBinding

	// Renders are the resolved whole-source renders (berm.dotenv, berm.envdir).
	Renders []RenderBinding

	// EnvExposure is set when the plan delivers any env, so berm status can
	// surface the one-time honesty warning that env-delivered secrets are
	// readable via /proc/<pid>/environ inside the container and by host root.
	EnvExposure bool
}

// resolver holds the per-container context the delivery-resolution helpers
// share.
type resolver struct {
	cfg           *config.Config
	service       string
	defaultSource string
	containerUser string

	// containerOwner and containerMode are the container-level berm.owner /
	// berm.mode defaults. They sit between a per-file (or per-render) override and
	// the built-in fallback, and apply to every file and render delivery. Empty
	// when the label is unset.
	containerOwner string
	containerMode  string
}

// Resolve parses the container's labels, then validates and resolves them
// against berm.yml into a Plan. It returns (nil, nil) for an inert container
// (berm.enable absent or not true), a *label.Error for any validation failure
// (skip-and-alert, sticky when secrets-affecting), and a *Plan on success.
func Resolve(in Input) (*Plan, error) {
	if in.Config == nil {
		return nil, mkErr(label.ClassBadConfig, nil, "berm.yml is not loaded")
	}

	spec, err := label.Parse(in.Labels)
	if err != nil {
		return nil, err
	}
	if !spec.Enabled {
		return nil, nil
	}

	// Service identity: the authenticated identity the caller passed, honoring a
	// berm.name override if the caller did not fold it in.
	service := firstNonEmpty(in.Service, spec.Name)
	if service == "" {
		return nil, mkErr(label.ClassBadConfig, nil, "container has no resolvable service identity")
	}

	r := &resolver{
		cfg:            in.Config,
		service:        service,
		defaultSource:  firstNonEmpty(spec.Source, service),
		containerUser:  in.ContainerUser,
		containerOwner: spec.Owner,
		containerMode:  spec.Mode,
	}

	// Delivery mechanism: the label, else the effective BERM_DEFAULT_DELIVERY,
	// else the berm.yml defaults block. No inference beyond that.
	mech := spec.Delivery
	if mech == "" {
		mech = in.DefaultDelivery
	}
	if mech == "" {
		mech = delivery.Mechanism(in.Config.Defaults.Delivery)
	}
	if !mech.Valid() {
		return nil, mkErr(label.ClassBadConfig, map[string]string{"delivery": string(mech)},
			"no valid delivery mechanism from berm.delivery, BERM_DEFAULT_DELIVERY, or berm.yml defaults")
	}

	plan := &Plan{
		Container: in.ContainerID,
		Service:   service,
		Mechanism: mech,
	}

	// Env delivery gate: env is legal only on the client mechanism, which is the
	// only one that controls the process environment at exec. It is refused
	// outright on hook and volume.
	if len(spec.Env) > 0 && !delivery.EnvAllowed(mech) {
		return nil, mkErr(label.ClassEnvWrongMechanism, map[string]string{"delivery": string(mech)},
			"env delivery requires the client mechanism, refused on %s", mech)
	}

	for _, ed := range spec.Env {
		eb, e := r.resolveEnv(ed)
		if e != nil {
			return nil, e
		}
		plan.Env = append(plan.Env, eb)
	}
	if len(plan.Env) > 0 {
		plan.EnvExposure = true
	}

	for _, fd := range spec.Files {
		fb, e := r.resolveFile(fd)
		if e != nil {
			return nil, e
		}
		plan.Files = append(plan.Files, fb)
	}

	if spec.Dotenv != "" {
		rb, e := r.resolveRender(RenderDotenv, spec.Dotenv, spec.Owner, spec.Mode)
		if e != nil {
			return nil, e
		}
		plan.Renders = append(plan.Renders, rb)
	}
	if spec.Envdir != "" {
		rb, e := r.resolveRender(RenderEnvdir, spec.Envdir, spec.Owner, spec.Mode)
		if e != nil {
			return nil, e
		}
		plan.Renders = append(plan.Renders, rb)
	}

	return plan, nil
}

// resolveEnv resolves one env delivery, enforcing the all sentinel's
// owned-source rule and the ref-shape and grant rules for a keyed ref.
func (r *resolver) resolveEnv(ed label.EnvDelivery) (EnvBinding, *label.Error) {
	if ed.All {
		src, ok := r.cfg.Sources[r.defaultSource]
		if !ok {
			return EnvBinding{}, r.missingSource(r.defaultSource)
		}
		format, e := sourceFormat(r.defaultSource, src)
		if e != nil {
			return EnvBinding{}, e
		}
		if format != backend.FormatDotenv {
			return EnvBinding{}, mkErr(label.ClassWrongRefShape, map[string]string{"source": r.defaultSource},
				"berm.env=all needs a dotenv default source, but %q is binary", r.defaultSource)
		}
		if !serviceOwns(r.service, r.defaultSource, src) {
			return EnvBinding{}, mkErr(label.ClassAllCrossService, map[string]string{"source": r.defaultSource, "service": r.service},
				"berm.env=all is legal only on the container's own owned default source, not on %q", r.defaultSource)
		}
		return EnvBinding{All: true, Source: r.defaultSource}, nil
	}

	name, _, _, key, e := r.resolveRef(ed.Ref)
	if e != nil {
		return EnvBinding{}, e
	}
	return EnvBinding{Var: ed.Var, Source: name, Key: key}, nil
}

// resolveFile resolves one file delivery. An unset from ref defaults to the
// default source's whole payload, which is valid only when that source is
// binary.
func (r *resolver) resolveFile(fd label.FileDelivery) (FileBinding, *label.Error) {
	from := fd.From
	if isUnsetRef(from) {
		from = label.Ref{Kind: label.RefSource, Source: r.defaultSource}
	}

	name, format, whole, key, e := r.resolveRef(from)
	if e != nil {
		return FileBinding{}, e
	}

	path := fd.Path
	if path == "" {
		path = "/run/berm/" + fd.Name
	}
	pointer := ""
	if !whole {
		pointer = key + "_FILE"
	}

	return FileBinding{
		Name:       fd.Name,
		Source:     name,
		Format:     format,
		Whole:      whole,
		Key:        key,
		Path:       path,
		Owner:      firstNonEmpty(fd.Owner, r.containerOwner, r.ownerDefault()),
		Mode:       firstNonEmpty(fd.Mode, r.containerMode, r.modeDefault()),
		PointerVar: pointer,
	}, nil
}

// resolveRender resolves a whole-source render (dotenv or envdir) against the
// default source, which must exist, be dotenv, and be readable by the service.
func (r *resolver) resolveRender(kind RenderKind, path, owner, mode string) (RenderBinding, *label.Error) {
	src, ok := r.cfg.Sources[r.defaultSource]
	if !ok {
		return RenderBinding{}, r.missingSource(r.defaultSource)
	}
	format, e := sourceFormat(r.defaultSource, src)
	if e != nil {
		return RenderBinding{}, e
	}
	if format != backend.FormatDotenv {
		return RenderBinding{}, mkErr(label.ClassWrongRefShape, map[string]string{"source": r.defaultSource},
			"a whole-source render needs a dotenv default source, but %q is binary", r.defaultSource)
	}
	if !serviceMayRead(r.service, r.defaultSource, src) {
		return RenderBinding{}, r.ungranted(r.defaultSource)
	}
	return RenderBinding{
		Kind:   kind,
		Source: r.defaultSource,
		Format: format,
		Path:   path,
		Owner:  firstNonEmpty(owner, r.ownerDefault()),
		Mode:   firstNonEmpty(mode, r.modeDefault()),
	}, nil
}

// resolveRef resolves one secret reference to a concrete source, enforcing
// existence, shape versus format, and the owner-plus-grant scoping rule.
func (r *resolver) resolveRef(ref label.Ref) (name string, format backend.SourceFormat, whole bool, key string, err *label.Error) {
	switch ref.Kind {
	case label.RefKey:
		name = r.defaultSource
	case label.RefSourceKey, label.RefSource:
		name = ref.Source
	}

	src, ok := r.cfg.Sources[name]
	if !ok {
		return "", "", false, "", r.missingSource(name)
	}
	format, e := sourceFormat(name, src)
	if e != nil {
		return "", "", false, "", e
	}

	switch ref.Kind {
	case label.RefKey, label.RefSourceKey:
		if format != backend.FormatDotenv {
			return "", "", false, "", mkErr(label.ClassWrongRefShape, map[string]string{"source": name},
				"a key reference needs a dotenv source, but %q is binary", name)
		}
		whole, key = false, ref.Key
	case label.RefSource:
		if format != backend.FormatBinary {
			return "", "", false, "", mkErr(label.ClassWrongRefShape, map[string]string{"source": name},
				"a whole-source reference needs a binary source, but %q is dotenv", name)
		}
		whole = true
	}

	if !serviceMayRead(r.service, name, src) {
		return "", "", false, "", r.ungranted(name)
	}
	return name, format, whole, key, nil
}

func (r *resolver) ownerDefault() string { return firstNonEmpty(r.containerUser, "0:0") }

func (r *resolver) modeDefault() string { return firstNonEmpty(r.cfg.Defaults.Mode, "0400") }

func (r *resolver) missingSource(name string) *label.Error {
	return mkErr(label.ClassMissingSource, map[string]string{"source": name, "service": r.service},
		"source %q is not defined in berm.yml", name)
}

func (r *resolver) ungranted(name string) *label.Error {
	return mkErr(label.ClassUngrantedRef, map[string]string{"source": name, "service": r.service},
		"service %q may not read source %q: it is not the owner and the source's access list does not name it", r.service, name)
}

// sourceFormat maps a berm.yml source's declared format to a backend
// SourceFormat, defaulting an empty format to dotenv. An unrecognized format is
// a berm.yml error.
func sourceFormat(name string, src config.Source) (backend.SourceFormat, *label.Error) {
	if src.Format == "" {
		return backend.FormatDotenv, nil
	}
	f := backend.SourceFormat(src.Format)
	if !f.Valid() {
		return "", mkErr(label.ClassBadConfig, map[string]string{"source": name, "format": src.Format},
			"source %q has an unrecognized format %q", name, src.Format)
	}
	return f, nil
}

// serviceOwns reports whether service owns the named source, which lets it read
// the source with no grant and is the requirement for the all sentinel.
//
// Ownership is strict exact-name, faithful to the frozen grammar (Scoping Fork
// 4): a source's effective owner is its explicit owner: field, or, when that is
// unset, the source's own name. A service owns the source if and only if that
// effective owner equals the service identity. There is no prefix or namespace
// rule: a service reading a differently-named source it does not explicitly own
// requires that source's access list to name it, exactly like any other
// cross-service read. So a source shared under a service's own name is expressed
// by setting owner: <service> on it (as the worked example's webapp-tls does),
// never inferred from a shared name prefix.
func serviceOwns(service, name string, src config.Source) bool {
	owner := src.Owner
	if owner == "" {
		owner = name
	}
	return owner == service
}

// serviceMayRead reports whether service may read the named source: it owns the
// source, or the source's access list names it. No wildcards in v1.
func serviceMayRead(service, name string, src config.Source) bool {
	if serviceOwns(service, name, src) {
		return true
	}
	for _, a := range src.Access {
		if a == service {
			return true
		}
	}
	return false
}

// isUnsetRef reports whether a Ref is the zero value, meaning a berm.file
// delivery had no explicit from label.
func isUnsetRef(ref label.Ref) bool {
	return ref.Kind == label.RefKey && ref.Key == "" && ref.Source == ""
}

// mkErr is a thin constructor bridging to label's classified Error so resolve
// and label share one taxonomy.
func mkErr(class label.Class, fields map[string]string, format string, args ...any) *label.Error {
	return label.NewError(class, fields, format, args...)
}

// firstNonEmpty returns the first non-empty string, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
