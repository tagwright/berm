<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Operations

Deploying and running berm: the three delivery modes, rotating a secret, the CLI
workflows, and the environment globals. The runnable compose files this document
describes are in [../deploy](../deploy).

The daemon image is `ghcr.io/tagwright/berm:00.01.00b1`. The tag matches the
binary's `berm version`.

## What every deployment has in common

- **The age key lives only with the daemon.** It is mounted read-only into the
  berm service and into no app container. A compromised app never obtains the key,
  only its own declared secrets.
- **No daemon egress.** The daemon reads local ciphertext and a local key and
  never phones out, so the examples give it `network_mode: none`. The distroless
  image carries no shell and no network tooling. The runtime setting removes the
  route out. If you later wire beacon push telemetry to a local collector, swap
  `network_mode: none` for an internal (`internal: true`, gateway-less) network
  that reaches only that collector.
- **`pid: host` on the daemon** (client and hook modes). See below.
- **`berm.yml` is structure, not secrets**, so it is safe to commit. The examples
  reuse [../berm.example.yml](../berm.example.yml).
- **Secrets are ciphertext at rest.** The `*.sops.env` and `*.sops.bin` files
  under `BERM_SOURCES_ROOT` are age-encrypted and mounted read-only.

### Why `pid: host`

The daemon authenticates a caller by its socket peer credential and walks `/proc`
in the host PID namespace: `SO_PEERCRED` gives the caller's PID, then
`/proc/<pid>/cgroup` gives the container id, then the runtime gives its labels.
That walk resolves only in the host PID namespace. Without `pid: host` the kernel
reports the peer PID as `0` and the authenticator fails closed: it authenticates
nobody rather than guessing, which is the safe failure but means no secret is
delivered. This was proven live, both the success and the fail-closed, and is
recorded in [EMPIRICAL.md](EMPIRICAL.md). `--cgroupns=host` is **not** required:
under the default private cgroup namespace the peer's cgroup appears in a relative
`/../docker-<id>.scope` form that the parser handles, which keeps the daemon's own
cgroup isolation.

## Provisioning the age key with SOPS at deploy time

The daemon needs the plaintext age key file at the path `berm.yml` names (the
examples use `/run/berm/age/default.key`). Keep the key age-encrypted at rest and
decrypt it into place in your deploy step, the same way the rest of the suite
provisions a daemon's key:

```sh
mkdir -p ./secrets/age
sops -d age-default.key.sops > ./secrets/age/default.key
chmod 0400 ./secrets/age/default.key
```

Never commit the decrypted key. The examples mount `./secrets/age` read-only into
the daemon only. The repo `.gitignore` already excludes `*.key`. The daemon holds
only the path: `sops` reads the key file itself at decrypt time, from the
`SOPS_AGE_KEY_FILE` the backend sets in a minimal subprocess environment. The key
material never enters the berm process and is never passed on argv.

## The three modes

| Mode | Runtime primary | Consumer plumbing | Env-capable |
|---|---|---|---|
| `client` | Docker | `berm-client exec -- <app>` entrypoint, daemon socket shared to the app | yes (double-gated) |
| `hook` | Podman | OCI pre-start hook installed on the host | no |
| `volume` | both | tmpfs named volume plus a waiter service | no |

Env delivery is refused outright in hook and volume mode, because neither can
control the process environment. Env is client-mode only, and even there it needs
the second explicit `berm.env.acknowledge=true` per container.

### Client mode (Docker primary)

Full example: [../deploy/client](../deploy/client). The app's entrypoint is
wrapped as `berm-client exec -- <app>`. On start `berm-client` connects to the
daemon over the shared, peer-authenticated socket, receives only this container's
own declared secrets, delivers them to tmpfs, sets any acknowledged env, and execs
the real process. It is the only mode that can deliver env.

The daemon listens on a socket in a dedicated shared volume, kept separate from
the app's own `/run/berm` tmpfs where delivered files land:

```yaml
  berm:
    image: ghcr.io/tagwright/berm:00.01.00b1
    command: ["daemon", "--config", "/etc/berm/berm.yml", "--socket", "/run/berm-sock/berm.sock"]
    pid: host
    network_mode: none
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./berm.yml:/etc/berm/berm.yml:ro
      - ./secrets/sources:/var/lib/berm/sources:ro
      - ./secrets/age:/run/berm/age:ro
      - berm-sock:/run/berm-sock
      - berm-state:/var/lib/berm
    environment:
      BERM_SOURCES_ROOT: /var/lib/berm/sources
      BERM_DEFAULT_DELIVERY: client
    restart: unless-stopped
```

The app image lifts `berm-client` out of the published image (a static binary, so
no download and no checksum) and wraps its entrypoint. It reaches the daemon
socket through the shared `berm-sock` volume, and points the client at it with
`BERM_SOCK=/run/berm-sock/berm.sock`. A unix `connect()` needs write on the
socket, so that mount is not read-only. Delivered secrets land on the app's own
`/run/berm` tmpfs. A client-mode container whose fetch never completes within
`BERM_CLIENT_TIMEOUT` (default 30s) surfaces a client-fetch-timeout alert naming
the container, so a forgotten wrapper is an alert, not a container hung forever.

### Hook mode (Podman primary)

Full example and install steps: [../deploy/hook](../deploy/hook). An OCI pre-start
hook writes each berm-enabled container's secret files into the container's own
mount namespace before PID 1. There is no client binary in the app image, no
entrypoint change, and no start race. Files only.

Install `berm-hook` on the host (lift it out of the published image), install the
hook definition, and make sure Podman scans the hooks directory:

```sh
id=$(sudo podman create ghcr.io/tagwright/berm:00.01.00b1)
sudo podman cp "$id":/usr/local/bin/berm-hook /usr/local/bin/berm-hook
sudo podman rm "$id"
sudo chmod 0755 /usr/local/bin/berm-hook

sudo install -D -m 0644 deploy/hook/hooks.d/berm-hook.json \
  /etc/containers/oci/hooks.d/berm-hook.json

sudo mkdir -p /etc/containers
printf '[engine]\nhooks_dir = ["/etc/containers/oci/hooks.d"]\n' \
  | sudo tee -a /etc/containers/containers.conf
```

Two corrections the integration campaign proved live, both reflected in the shipped
hook definition and worth understanding:

- **The stage is `createContainer`, not `createRuntime`.** The hook definition
  ships `"stages": ["createContainer"]`. At `createRuntime` the hook fires
  host-side before the container's mounts exist, so the tmpfs the secret must land
  on is not present. `createContainer` runs the hook inside the container's own
  mount namespace after the mounts are set up but before `pivot_root`, and
  `berm-hook` writes the files under the container rootfs the OCI state names.
- **The trigger is an OCI annotation, and the daemon resolves from presented
  annotations.** The `when.annotations` match fires the hook only for containers
  carrying the `berm.enable=true` OCI **annotation**. On current Podman a container
  label is not surfaced as an annotation, so a hook-mode container carries
  `berm.enable` in **both** places: as an annotation (the trigger) and as a label
  (with the rest of the `berm.*` config, which the daemon reads). Set the
  annotation with `--annotation berm.enable=true` (`podman run`) or the compose
  `annotations:` block:

```yaml
  example-app:
    image: docker.io/library/postgres:16
    annotations:
      berm.enable: "true"
    labels:
      berm.enable: "true"
      berm.name: "example-app"
      berm.delivery: "hook"
      berm.file.pgpass.from: "POSTGRES_PASSWORD"
    environment:
      POSTGRES_PASSWORD_FILE: /run/berm/pgpass
    tmpfs:
      - /run/berm
```

The hook presents the container's own OCI annotations in its request, and the
daemon resolves the plan from those without inspecting the container over the
runtime API. It must, because the pre-start hook fires while the runtime holds the
container-creation lock, and a daemon Inspect of that same container would deadlock
against the create the hook is blocking (found live). The daemon still validates
the presented config against `berm.yml`: service scoping, ref shape, owner plus
grants, and files-only. Hook mode cannot set an env var, so point the app at the
file explicitly with the `_FILE` env var (the auto-set pointer is an env var and so
is unavailable in hook mode). The daemon binds its socket to the host `/run/berm`
so the host-side hook can reach it at `berm-hook`'s default `/run/berm/berm.sock`.

### Volume mode (both runtimes, no image change)

Full example: [../deploy/volume](../deploy/volume). The daemon populates a
tmpfs-backed **named** volume (a bare tmpfs mount is not shareable between
containers) shared with the app. A waiter service blocks on the atomic appearance
of the delivered manifest, and the app `depends_on` the waiter's clean completion,
which closes the container-start race.

Two things the integration campaign corrected here:

- **The daemon-side mount path must be `/run/berm/volumes/<berm.volume>`.** The
  daemon writes each volume-mode secret to `<DefaultVolumeMountRoot>/<berm.volume>`
  = `/run/berm/volumes/<berm.volume>`, so the daemon-side mount of the app's volume
  must be exactly that path. A mismatch leaves the app unpopulated and the waiter
  blocked forever.
- **The daemon reconciles created-but-not-started containers.** Compose creates the
  app up front and gates its start on the waiter, so the daemon populates a
  volume-mode container that has been created but not yet started, rather than
  waiting for a start event that the waiter is blocking. Without this the shipped
  turnkey compose deadlocked.

The named volume must be tmpfs-backed (`driver_opts: {type: tmpfs, device:
tmpfs}`) so a secret never lands on persistent disk. The daemon refuses a
non-tmpfs target. The waiter can be a tiny busybox polling for the manifest: the
manifest carries names, paths, and ciphertext hashes, never a value, so polling
for it leaks nothing.

## Rotation: recreate to pick up a new secret

There is no live-reload in v1. A persistent in-container agent is deliberately not
built, and live-reload would collide with hard rules like never restarting certain
databases. Rotation follows the recreate-to-pick-up-new-secrets discipline the
rest of the homelab already uses:

1. Edit and re-encrypt the source (`sops <source>.sops.env`, or `sops -e -i` on a
   fresh plaintext file).
2. Recreate the affected container so its secret is re-injected at start:
   - Docker: `docker compose up -d --no-deps <service>`.
   - Podman: recreate the container (`podman-compose up -d`, or recreate the
     unit/quadlet).

To know **what** is stale, the daemon records a ciphertext hash per injection
(nothing secret) and `berm stale` reports which containers hold a source that
changed since their last injection. You recreate on your own schedule, with full
knowledge of what is stale.

## The CLI

All read-only companion commands operate on names, paths, hashes, and structure
only. None decrypts a secret or prints a value. Each takes `--config`
(default `/etc/berm/berm.yml`). `status` and `stale` also take `--ledger`
(default `/var/lib/berm/ledger.json`).

- **`berm validate`** dry-runs the manifest with no injection and no decryption. It
  enumerates every berm-enabled container, resolves each against `berm.yml` the way
  the daemon would, prints what would be delivered (source, key or whole payload,
  target, mechanism, owner, mode) and every validation error with its class, and
  exits nonzero when any container fails. That nonzero exit makes it a pre-deploy CI
  gate.
- **`berm status`** prints a table of every enabled container's injection state:
  service, resolved mechanism, delivery targets, whether the ledger records an
  injection, whether a source has drifted since, and any standing validation error.
  Below the table it surfaces two things prominently so they cannot scroll away: the
  one-time env-exposure warning for every container that delivers env, and every
  sticky secrets-affecting error, held until fixed.
- **`berm stale`** reports which containers hold a source that changed since their
  last injection, and which recreate command to run. It is standalone: it reads the
  persisted ledger and compares each recorded ciphertext hash to the source on disk
  now, without needing the daemon running. A source deleted since injection surfaces
  as loudly as a changed one.
- **`berm suggest <service>`** is the migration on-ramp. Given a service and its
  existing hand-rolled sops-encrypted file, it reads only the cleartext key names
  (sops keeps dotenv keys in cleartext and encrypts only values as `ENC[...]`) and
  prints ready-to-paste berm labels and the matching `berm.yml` sources stanza. File
  delivery is led with. The env-shaped alternative is emitted commented-out and
  annotated as the exposed path. It proposes, you commit: nothing is auto-written. It
  never runs `sops -d`, never decrypts, and never prints a value. The source file
  comes from `--file`, else the `berm.yml` source entry, else the convention
  `<BERM_SOURCES_ROOT>/<service>.sops.env`. The format comes from `--format`, else
  `berm.yml`, else the file extension.
- **`berm version`** prints the build version.

## Environment globals

The small surviving set of `BERM_*` env on the daemon container. They are env, not
committed `berm.yml` fields.

| Variable | Default | Meaning |
|---|---|---|
| `BERM_SOURCES_ROOT` | unset | Root under which relative `file:` paths in `berm.yml` resolve. |
| `BERM_DEFAULT_DELIVERY` | per runtime | Fleet default for `berm.delivery`, itself defaulting per runtime (Docker `client`, Podman `hook`). |
| `BERM_CLIENT_TIMEOUT` | `30s` | Client-mode fetch deadline, past which the container alerts. |
| `BERM_STALE_DIGEST` | off | Enable the scheduled rotation-drift digest. |
| `BERM_DIGEST_SCHEDULE` | `daily` | The digest cadence. |
| `BERM_RUNTIME` | `docker` | Which runtime to drive: `docker` or `podman`. Also decides the per-runtime default delivery when `BERM_DEFAULT_DELIVERY` is unset. |
| `BERM_SOCKET` | conventional path | The container-runtime socket the daemon talks to. When unset, the daemon falls back to the runtime's conventional socket (`/var/run/docker.sock` for Docker, `/run/podman/podman.sock` for Podman) rather than an empty one. |

The daemon's own listen socket (what the client and hook connect to) is separate:
it is set with the `daemon --socket` flag, default `/run/berm/berm.sock`. The
consumer binaries find it via `BERM_SOCK` (client) / `BERM_SOCK` (hook), or their
`--sock` flag, default `/run/berm/berm.sock`. Note the distinction: `BERM_SOCKET`
is the runtime socket the daemon reads. `BERM_SOCK` is where a consumer dials the
daemon.

The consumer binaries also read a few env vars for testing and tuning:
`BERM_CLIENT_TIMEOUT` / `BERM_HOOK_TIMEOUT` (fetch deadlines),
`BERM_MANIFEST_PATH` (the in-container manifest path, default `/run/berm/manifest`),
and `BERM_CLIENT_ALLOW_NONTMPFS=1` / `BERM_HOOK_ALLOW_NONTMPFS=1` to relax the
tmpfs-only destination rule (testing only, never in production).

The daemon does not create the deliberately-cut footguns: there is no global
default source (it would cross-wire secrets on a typo), no fleet-wide injection (a
shared value is a granted shared source each consumer still declares), no global
owner or mode override, and no global env-delivery default (env stays per-container
behind the acknowledgment gate).

## Releases

Images are published to `ghcr.io/tagwright/berm` when a `v*` tag is pushed. After
the first publish, flip the ghcr package's visibility to public once in the GitHub
package settings: a newly created package defaults to private regardless of what
the workflow pushes. The image tag is derived from the raw ref, not a semver
pattern, so the suite's zero-padded non-semver tag (`v00.01.00b1` publishing
`:00.01.00b1`) is not silently dropped in favor of only `:latest`, and it matches
the binary's `berm version`.
