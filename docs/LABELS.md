<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Label reference

This is the authoritative reference for every berm label, derived from the code
(`internal/label`, `internal/resolve`, `internal/config`). Where it differs from
the frozen design grammar, the code is the source of truth and the difference is
called out inline.

A label names a secret. It never contains one. No secret value appears in a
label or in `berm.yml`.

## Two doorways, one grammar

Every label has two spellings with identical meaning:

- `berm.<suffix>` is the primary, tool-branded form. Lead with it.
- `tagwright.secret.<suffix>` is the org-namespaced alias. Its suffixes are
  identical: `berm.enable` and `tagwright.secret.enable` mean the same thing.

The reader strips whichever prefix matches and parses one suffix grammar. The
same suffix under both prefixes with **different** values is a validation error
(`cross_prefix_conflict`). The same value under both is harmless. A label under
neither prefix is ignored.

An unknown `berm.*` suffix is a validation error (`unknown_suffix`), not a silent
skip. A mistyped `berm.fille.db.path` fails loudly, because a silently-absent
secret is a production outage found at the worst time.

## Opt-in

A container is inert until it opts in:

| Label | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `berm.enable` | bool | absent | yes | Opt the container into injection. Absent or `"false"` is identical: the container is skipped, never alerted. |

All label values are strings. Booleans are `"true"` / `"false"`.

## Identity and mechanism

| Label | Type | Default | Meaning |
|---|---|---|---|
| `berm.name` | string | compose service name | The service identity. Keys the default source and the scoping identity. Replicas (duplicate service names) deliberately share one identity and one set of grants. |
| `berm.source` | source name | service name | The default source that every bare `KEY` ref and every whole-source render resolves against. Must match the source-name shape below. A reference to a source not in `berm.yml` is a validation error (`missing_source`), never a silent empty delivery. |
| `berm.delivery` | enum | `BERM_DEFAULT_DELIVERY` | One of `client`, `hook`, `volume`. No inference beyond the default. Env delivery requires `client`. |
| `berm.volume` | string | `berm-<service>` | The tmpfs mount name used in volume-mode delivery. |

The delivery mechanism resolves in this order: the `berm.delivery` label, else
`BERM_DEFAULT_DELIVERY`, else the per-runtime default (Docker `client`, Podman
`hook`), else the `berm.yml` `defaults.delivery` block, else `client`. A
mechanism that cannot be resolved is a `bad_config` error.

## Secret reference grammar

Wherever a label names a secret, it uses one reference grammar:

```
ref := KEY | source "/" KEY | source
```

- `KEY` alone reads that key from the container's default source
  (`berm.source`, defaulting to the service name).
- `source/KEY` reads a named key from a named dotenv source.
- `source` alone takes the whole payload of a source, and is valid **only** for a
  source whose `format` is `binary`.

Character classes, which never overlap, so the single `/` separator is
unambiguous and no escaping is ever needed:

- A **key** is dotenv-env-var shaped: an uppercase letter or underscore followed
  by uppercase letters, digits, and underscores (`^[A-Z_][A-Z0-9_]*$`).
- A **source** name is a lowercase identifier: lowercase letters and digits, with
  internal dashes, not leading or trailing with a dash
  (`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`).

Shape versus format is checked at resolve time against `berm.yml`, because format
is a property of the source, never restated in a label:

- A bare `source` ref against a **dotenv** source is a `wrong_ref_shape` error (a
  dotenv source has keys, not one payload).
- A `source/KEY` (or bare `KEY`) ref against a **binary** source is a
  `wrong_ref_shape` error (a binary source has one payload, not keys).

## File delivery (the secure default)

Files are the default and the recommended path. A secret at a tmpfs path with a
tight owner and mode is not visible in `docker inspect` and not visible to other
users on the host.

| Label | Type | Default | Meaning |
|---|---|---|---|
| `berm.file.<name>.from` | ref | the default source's whole payload, when that source is binary | What to deliver into the file. |
| `berm.file.<name>.path` | absolute path | `/run/berm/<name>` | The tmpfs-backed target. Deliberately not `/run/secrets/<name>`, to avoid shadowing compose's own secrets mounts. |
| `berm.file.<name>.owner` | `uid[:gid]` | `berm.owner`, else the container's configured user, else `0:0` | Numeric only, no names. |
| `berm.file.<name>.mode` | octal string | `berm.mode`, else `defaults.mode` in `berm.yml`, else `0400` | Three or four octal digits (`"0400"`, `"440"`). |

`<name>` is a delivery label of your choosing. It may itself contain dots (the
final segment is the attribute), but not a `/`. The recognized attributes are
exactly `from`, `path`, `owner`, and `mode`. Any other is an `unknown_suffix`
error.

The `_FILE` pointer: for a keyed file delivery, berm auto-sets the non-secret
`<KEY>_FILE` env var to the delivered path (for a `POSTGRES_PASSWORD` key, it sets
`POSTGRES_PASSWORD_FILE`). The value is a path, not a secret, so it trips no env
exposure and needs no acknowledgment, and it serves the dominant `_FILE`
convention in one label. A whole-payload (binary) delivery has no key to name a
pointer after, so it sets none. The pointer is an env var, so it is emitted only
on a mechanism that controls the environment (client). In hook and volume modes
it is recorded in the manifest instead of set.

### Container-level owner and mode

| Label | Type | Default | Meaning |
|---|---|---|---|
| `berm.owner` | `uid[:gid]` | the container's configured user, else `0:0` | Container-level default owner. Numeric only. |
| `berm.mode` | octal string | `defaults.mode`, else `0400` | Container-level default mode. |

`berm.owner` and `berm.mode` are container-level defaults for **every** delivery
on the container, both `berm.file.<name>` deliveries and whole-source renders
(`berm.dotenv`, `berm.envdir`). Each is overridable per file. The precedence, the
same for both owner and mode across files and renders:

- **owner**: the per-file `berm.file.<name>.owner`, else the container-level
  `berm.owner`, else the container's configured user, else `0:0`.
- **mode**: the per-file `berm.file.<name>.mode`, else the container-level
  `berm.mode`, else `defaults.mode` in `berm.yml`, else `0400`.

The container-level tier sits between the per-file override and the built-in
fallback. There is deliberately no fleet-wide owner override anywhere: a single
line must not be able to silently downgrade every secret's permissions across the
fleet, and the container-level default only ever affects one container's own
deliveries.

## Whole-source renders

Two shapes render an entire dotenv source at once. Both are file-mode, both
operate on the default source only, and both honor the container-level
`berm.owner` / `berm.mode` defaults.

| Label | Type | Default | Meaning |
|---|---|---|---|
| `berm.dotenv` | absolute path | unset | Render the whole default source as one `KEY=VALUE` dotenv file at that path. |
| `berm.envdir` | absolute path | unset | Render the whole default source key-per-file under that directory, the s6-overlay `container_environment` style, one file per key named for the key. |

A whole-source render needs a dotenv default source. Against a binary source it is
a `wrong_ref_shape` error.

## Env delivery (the exposed path, double-gated)

Env delivery is the one exposed path. An env-delivered secret is readable via
`/proc/<pid>/environ` from inside the container and by host root, which a file at
mode `0400` owned by the app user is not. Everything about it is built to make the
exposure deliberate and visible.

| Label | Type | Default | Meaning |
|---|---|---|---|
| `berm.env` | csv of refs, or `all` | none | Refs delivered into the process environment, each var named for the ref's `KEY`. The `all` sentinel expands to every key of the owned default source. Client mode only. |
| `berm.env.<VAR>` | ref | none | One ref delivered as env var `<VAR>`. The rename form and the cross-source form, since `<VAR>` need not match the source key. Client mode only. |
| `berm.env.acknowledge` | bool | absent | Required with any `berm.env*` label. Absent makes any `berm.env*` label a hard `env_no_acknowledge` error, not a warning. |

The two gates:

1. **Mechanism.** Env is delivered only through the client wrapper, which is the
   only mechanism that controls the process environment at exec. Any env label
   under `hook` or `volume` is an `env_wrong_mechanism` error. A silent no-op there
   would be worse than an error.
2. **Acknowledgment.** Any `berm.env*` label requires `berm.env.acknowledge=true`
   on the same container. Copy-pasting env labels from another service does not
   carry the exposure, because the acknowledgment does not travel with them.

An env ref must name a key. A bare `source` ref (a whole binary payload) has no
key to name a var after, and is a `wrong_ref_shape` error.

The `all` sentinel is legal **only** on the container's own owned default source,
and only when that source is dotenv. It is never legal across a cross-service
grant (`all_cross_service` error), so no single label ever blanket-grants another
service's whole payload into the environment.

Even with the acknowledgment, `berm status` and `berm validate` surface a
one-time honesty note for every container that delivers env, naming the exposure.

## Scoping: owner plus grants

This is the security-critical part, and it makes `berm.yml` the single audited
answer to who can read what. Ownership is **strict exact-name**:

- Every source in `berm.yml` has an effective owner: its explicit `owner:` field,
  or, when that is unset, the source's own name.
- A service **owns** a source if and only if that effective owner equals the
  service identity. The owner may read the source with no grant.
- Any **other** service must be named in the source's `access:` list. An
  ungranted reference is a sticky `ungranted_ref` error.

There is no prefix or namespace rule. A service reading a differently-named source
it should own must set `owner: <service>` on that source in `berm.yml` (as the
worked example's `webapp-tls` does), never inferred from a shared name prefix.
Cross-service sharing is therefore declared twice: once by the consumer's label,
once by the source's grant. Both must agree. There are no wildcard grants in v1.
Enumerate the services in `access:`. To share only one key of a source, split
that key into its own source and grant that.

Honesty about the threat model: this catches operator mistakes (copy-paste drift,
an over-broad `access:`, a consumer reaching for a source it should not). It does
not defend against a malicious operator, who writes the compose files and could
mount anything anyway. The runtime blast-radius guarantee, peer authentication of
the fetching container plus manifest scoping of what it receives, holds regardless
of grants and is the real containment boundary. See
[SECURITY.md](SECURITY.md).

## Reserved

| Label | Type | Meaning |
|---|---|---|
| `berm.rotate` | reserved | Rejected as a `rotate_reserved` validation error in v1, so a future additive auto-recreate opt-in can land without a grammar collision. |

## Validation classes

A validation failure skips exactly one container and alerts through beacon. It
never breaks injection for the rest of the fleet. Three classes are **sticky**,
held in the beacon digest until fixed, because they are secrets-affecting:
`ungranted_ref`, `missing_source`, and `env_no_acknowledge`. The full set of
class tokens, as they appear in `berm status`, `berm validate`, and the digest:

| Token | Meaning |
|---|---|
| `unknown_suffix` | An unrecognized `berm.*` / `tagwright.secret.*` suffix. |
| `cross_prefix_conflict` | The same suffix under both prefixes with different values. |
| `wrong_ref_shape` | A ref shape that does not match its source's format. |
| `missing_source` | A reference to a source not in `berm.yml` (sticky). |
| `ungranted_ref` | A cross-service read the owner and access list do not permit (sticky). |
| `env_no_acknowledge` | An `berm.env*` label without `berm.env.acknowledge=true` (sticky). |
| `env_wrong_mechanism` | An env delivery under `hook` or `volume`. |
| `all_cross_service` | `berm.env=all` against a source the container does not own. |
| `rotate_reserved` | The reserved `berm.rotate` label. |
| `malformed` | A syntactically invalid value: a bad enum, a non-numeric owner, a non-octal mode, a relative path, or an unparseable ref. |
| `bad_config` | No resolvable delivery mechanism, or no resolvable service identity. |

## Worked examples

### (a) Canonical minimal: one secret to a file

```yaml
services:
  firefly-db:
    image: postgres:16
    labels:
      berm.enable: "true"
      berm.file.pgpass.from: "POSTGRES_PASSWORD"
```

The default source is `firefly-db` (the service name). `POSTGRES_PASSWORD` from
that source lands at `/run/berm/pgpass`, tmpfs-backed, owned by the container's
configured user, mode `0400`. `POSTGRES_PASSWORD_FILE` is auto-set to the path,
so postgres reads its password from the file with nothing exposed in
`docker inspect`. The same thing through the org doorway:

```yaml
    labels:
      tagwright.secret.enable: "true"
      tagwright.secret.file.pgpass.from: "POSTGRES_PASSWORD"
```

### (b) The `berm.env=all` env-file replacement, with its acknowledgment

```yaml
services:
  paperless:
    image: ghcr.io/paperless-ngx/paperless-ngx
    labels:
      berm.enable: "true"
      berm.delivery: "client"
      berm.env: "all"
      berm.env.acknowledge: "true"
```

The default source is `paperless`. `all` expands to every key of that owned source,
delivered into the process environment by the client wrapper at exec, never into
`docker inspect`. `all` is legal here because `paperless` reads its own owned
default source. Without `berm.env.acknowledge: "true"` the whole container is an
`env_no_acknowledge` error, skipped and alerted. Moving these to `berm.file.*`
deliveries later drops the exposure and the acknowledgment.

### (c) Full spread: a renamed cross-service env key and a binary file

```yaml
services:
  webapp:
    image: example/webapp
    user: "1000:1000"
    labels:
      berm.enable: "true"
      berm.delivery: "client"
      berm.source: "webapp"
      berm.env.DATABASE_URL: "shared-db/DATABASE_URL"
      berm.env.acknowledge: "true"
      berm.file.tls-key.from: "webapp-tls"
      berm.file.tls-key.path: "/run/berm/tls/server.key"
      berm.file.tls-key.owner: "1000:1000"
      berm.file.tls-key.mode: "0440"
```

with, in `berm.yml`:

```yaml
sources:
  webapp:
    file: webapp.sops.env
    format: dotenv
  webapp-tls:
    file: webapp-tls.sops.bin
    format: binary
    owner: webapp
  shared-db:
    file: shared-db.sops.env
    format: dotenv
    owner: postgres
    access:
      - webapp
```

`berm.env.DATABASE_URL` delivers the `DATABASE_URL` key from `shared-db`, renamed
into the `DATABASE_URL` env var. It is a cross-service read: `shared-db` is owned
by `postgres` and lists `webapp` in `access:`, so label and grant agree. Because
this is a cross-service grant, `all` would not have been legal here. The
`webapp-tls` binary source is delivered whole (a bare `source` ref, valid only for
a binary source) to `/run/berm/tls/server.key`, owned `1000:1000`, mode `0440`,
both set per file. `webapp` owns `webapp-tls` because that source sets
`owner: webapp`, matching the service identity exactly. Nothing in either the
labels or `berm.yml` is a secret value.
