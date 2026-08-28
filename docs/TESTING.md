# Testing

berm is tested at two levels: the Go unit and library tests that ship with each
package, and two real integration harnesses that drive the actual daemon image
against live containers, one over a real Docker socket and one against a nested
Podman host. This document records what is proven, what is compile-only, and what
is unproven, honestly.

## Coverage matrix

| Capability | Status | Where |
|---|---|---|
| Client mode, file + env + binary delivery on Docker | proven live | Docker harness |
| Volume mode + turnkey compose convergence on Docker | proven live | Docker harness |
| Hook mode end to end (createContainer, own mount ns, before PID 1) on Podman | proven live | nested-Podman harness |
| Client and volume modes on Podman | proven live | nested-Podman harness |
| Peer-auth isolation, adversarial, both runtimes | proven live | both harnesses |
| No-store / no-log / no-plaintext-on-disk, age key never in an app | proven live | both harnesses |
| Every validation failure path (skip-and-alert) | proven live | Docker harness |
| Rotation staleness (`berm stale` drift) | proven live | Docker harness |
| Rootless Podman, daemon + hook end to end | unproven | needs a real rootless Podman host |
| cgroup v1 peer-auth | compile-only (unit fixtures) | live proof is cgroup v2 |

Across the two harnesses the integration campaign found and fixed **five** real
bugs, three on the Docker path and two on the Podman hook path, each in code that
unit tests could not reach. They are detailed in the two "bugs found and fixed"
sections below.

## Unit and library tests

`go test ./...` (in `golang:1.25`, with `GOPRIVATE=github.com/tagwright/*`) runs
the per-package tests. The backend, delivery, wire, label, resolve, peerauth,
hookd, client, cli, and daemon packages carry table and round-trip tests. The
daemon dispatch tests that need real crypto (`internal/daemon`, via
`realOpener`) run for real where `sops` and `age-keygen` are on PATH and skip
cleanly where they are not, so `go test ./...` is green on a bare CI image and
exercises the true SOPS/age path on a developer box with the pinned tools.

The peerauth SO_PEERCRED gates are proven live and documented in
[EMPIRICAL.md](EMPIRICAL.md).

## Integration harness (Docker path)

`test/integration/run.sh` is the real integration harness. It builds the berm
image, generates a fresh age key and real sops-encrypted fixture sources
(dotenv and binary), provisions the age key into the daemon only, runs the
daemon as a `berm-itest-*` container (`pid: host`, docker socket read-only,
`network_mode: none`, ciphertext and key read-only, a private socket volume),
and drives live app containers against it. Every object it creates is prefixed
`berm-itest-` and torn down in a trap that runs even on failure; the run ends
with a leak check over containers, volumes, and networks. There is no host Go
toolchain requirement: all Go builds run in `golang:1.25`.

Run it (needs a live Docker socket, host `sops`, and one-time network egress to
pull base images and build a static `age-keygen`):

```
bash test/integration/run.sh
```

It prints a PASS/FAIL line per assertion and a final tally, exiting nonzero if
any assertion failed or any `berm-itest-*` object leaked. The most recent full
run was 61 assertions, all passing, no leaks.

### Coverage: PROVEN (live, against real containers)

Client mode (the Docker primary):

- A file secret lands on tmpfs at the resolved path, byte-exact to the known
  plaintext, with the numeric owner and octal mode from the labels.
- The non-secret `<KEY>_FILE` pointer env var is set to the tmpfs path.
- An env-delivered secret (with `berm.env.acknowledge`) is present in the app
  process `/proc/1/environ` and ABSENT from `docker inspect`.
- A binary whole-payload delivery is byte-exact on tmpfs.

Volume mode:

- A tmpfs-backed named volume shared daemon/app: the waiter blocks while the
  manifest is absent, the daemon populates the volume, the waiter then unblocks,
  and the app reads its file secret byte-exact from the volume, on tmpfs.
- The shipped turnkey volume compose CONVERGES (regression for the deadlock
  bug below): `docker compose up -d` returns, the manifest waiter exits 0, and
  the gated app starts and reads its secret.

Security spine:

- Adversarial peer-auth isolation: container A receives only its own secret and
  never B's, and vice versa. An ungranted cross-service read is refused
  fail-closed (the client exits nonzero, no value delivered), the daemon
  classifies it `ungranted_ref`, it stays sticky in the scheduled digest, and
  the rest of the fleet is still served. A granted cross-service read succeeds.
- No-store / no-log / no-plaintext-on-disk: after a full injection cycle, every
  known plaintext value is absent from the daemon logs, the persisted ledger,
  and the daemon's writable layer; the age key is absent from every app
  container; and the delivered secret sits on tmpfs (statfs). Evidence below.

Failure paths (each a validation error, skip-and-alert, never a silent empty
delivery, never a fleet-wide break):

- env without `berm.env.acknowledge` -> `env_no_acknowledge` (sticky).
- env under the volume mechanism -> `env_wrong_mechanism`.
- unknown berm suffix -> `unknown_suffix`.
- cross-prefix conflict (different values) -> `cross_prefix_conflict`.
- missing source -> `missing_source` (sticky).
- bare-source ref against a dotenv source -> `wrong_ref_shape`.
- source/KEY ref against a binary source -> `wrong_ref_shape`.
- Client timeout: a client-mode container that never runs berm-client triggers
  a client-fetch-timeout alert naming the container within BERM_CLIENT_TIMEOUT.

Rotation:

- Staleness: after injection, re-encrypting a source's ciphertext makes
  `berm stale` report the container as drifted (ciphertext-hash comparison) with
  no value exposed.

### Coverage: COMPILE-ONLY / UNPROVEN (Docker harness)

- cgroup v1 is covered by peerauth unit fixtures only; the live Docker proof is
  Docker 29 / cgroup v2 / systemd (see EMPIRICAL.md). The live Podman topologies
  are covered by the nested-podman harness below.

## Integration harness (nested-Podman path)

`test/integration/run-podman.sh` is the second integration harness, the FIRST
live exercise of the Podman runtime, the OCI pre-start HOOK delivery, and the
container-mount-namespace write. Mirroring how ballast proved Podman, it stands
up a throwaway rootful Podman by running `quay.io/podman/stable` (`--privileged`,
for Podman's own nested runtime), loads the berm image into it, installs
`berm-hook` via Podman's `hooks_dir`, and runs the berm daemon (a Podman
container, `--pid host`), the OCI hook, and the app containers INSIDE that
Podman. Every object is prefixed `berm-itest-*` and torn down on exit, with a
final leak check. Run it (needs a live Docker socket, host `sops`, and network
egress once to pull `quay.io/podman/stable`, `docker.io/library/busybox`, and
build a static `age-keygen`):

```
bash test/integration/run-podman.sh
```

Verified live against Podman 5.8.4 / crun 1.28 / cgroup v2. Most recent run: 20
assertions, all passing, no leaks.

### Coverage: PROVEN (live, against a real Podman socket and crun-created containers)

Hook mode (the Podman primary), end to end:

- The `berm-hook` OCI hook, installed via `hooks_dir`, fires at the
  `createContainer` stage for a `berm.enable`-annotated container, connects to
  the daemon over the hook-request protocol, and writes the file secret into the
  container's OWN mount namespace, on tmpfs, BEFORE PID 1 (PID 1's first
  instruction already sees the file), byte-exact to the known plaintext, with the
  numeric owner (uid 1000) and mode (0440). The manifest lands on the tmpfs too.
- The age key never reaches the app container, and the secret plaintext exists
  ONLY on the tmpfs, never in the app's persistent rootfs (`podman export`).
- Files only: an env declaration under hook mode is refused end to end (the
  resolver + the hook handler refuse env), which fails that one container's start
  loudly (`env_wrong_mechanism`, no silent empty delivery), while the rest of the
  fleet is still served (a fresh files-only hook container still works).

Podman runtime for the other modes:

- Client mode works under Podman: the daemon selects the Podman runtime
  (`BERM_RUNTIME=podman`), peer-authenticates the caller through the libpod
  cgroup topology (`0::/libpod_parent/libpod-<id>`, exercising peerauth's cgroup
  parsing for real), and delivers the file secret byte-exact on tmpfs.
- Volume mode works under Podman: the daemon watches the live Podman event
  stream, populates the shared tmpfs named volume on the start event, the
  manifest appears as the ready signal, and the app reads its secret byte-exact.
- Compose/pod service identity: a hook-mode container with no `berm.name`,
  identified only by a `com.docker.compose.service` annotation, resolves to the
  matching source.

### Coverage: rootless-Podman observations (the architecture's flagged item)

Rootless Podman is exercised best-effort and reported honestly, not asserted
green:

- OBSERVED: the `createContainer` hook FIRES under rootless Podman (it runs as
  uid 0 inside the container user namespace), and the rootless OCI state carries
  the container rootfs path, so berm-hook's createContainer write path applies
  unchanged rootless.
- UNPROVEN (full rootless `berm-hook` -> daemon end to end): the harness daemon
  binds a ROOT-OWNED socket at `/run/berm/berm.sock`, which a rootless hook
  (running as the unprivileged user) cannot connect to. A real rootless deploy
  runs the daemon rootless too, with a user-owned socket. Standing up a fully
  rootless daemon + age-key chain was out of scope for this harness; the rootful
  hook path is fully proven above.

### Bug found and fixed by the nested-Podman pass

The integration streak held: this pass found two real bugs in the hook path,
both in code that unit tests and the Docker harness could not reach.

1. Wrong hook stage and write path. The hook shipped at the `createRuntime` stage
   and wrote via `setns` into `/run/berm` as `/`. Verified live: at
   `createRuntime` the hook fires host-side BEFORE the container mounts exist, so
   the tmpfs the secret must land on is not present and the write cannot reach it.
   Fixed to the `createContainer` stage (the architecture's intended stage), which
   runs the hook inside the container's own mount namespace after the mounts are
   set up but before `pivot_root`, and to write the bundle under the container
   rootfs path the OCI state carries (`WriteFilesUnderRoot`, no setns).
2. Inspect-during-createContainer deadlock. The daemon resolved a hook request by
   inspecting the container over the runtime API. The pre-start hook fires while
   Podman holds the container-creation lock, so the daemon's Inspect of that same
   container deadlocked against the create the hook was blocking (hook timed out,
   container start failed). Fixed by having the hook PRESENT the container's OCI
   annotations (its `berm.*` config, which the runtime hands the hook in the OCI
   state) in the hook request, so the daemon resolves from them without any
   runtime inspect. The daemon still validates the presented config against
   `berm.yml` (files-only, service scoping, owner-plus-grant). Consequence: in
   hook mode the `berm.*` config is set as OCI ANNOTATIONS (not labels), which is
   also what the hook `when` trigger already needs.

## Bugs found and fixed by the Docker integration pass

Every integration pass in this suite has found at least one real bug. The Docker
pass found three (the nested-Podman pass found two more, above, for five across
the campaign), all in paths unit tests could not reach:

1. Empty BERM_SOCKET produced the unparseable Engine API host `unix://`. With no
   BERM_SOCKET set (as the shipped deploy examples run), the core adapter built
   `client.WithHost("unix://" + "")`, so the daemon connected to nothing,
   authenticated no caller (every fetch refused "unauthenticated"), and watched
   no container. Fixed in `SelectRuntime` by falling back to the conventional
   socket path. Regression: `TestSocketOrDefaultNeverEmpty`.
2. Volume-mode turnkey deploy deadlocked. The daemon populated a volume only on
   the app's START event, but the shipped topology gates the app's start on a
   waiter that blocks on the manifest, so the start never fired and
   `docker compose up` hung forever. Fixed by a reconcile pass that populates a
   volume-mode container that has been CREATED but not started (compose creates
   it up front, which core's `List` returns). Regression:
   `TestReconcilePopulatesCreatedButNotStartedVolumeContainer` and the
   `volume-compose` phase in the harness.
3. The shipped `deploy/volume/docker-compose.yml` mounted the app volume
   daemon-side at `/run/berm-volumes/example-app`, but the daemon writes to
   `<DefaultVolumeMountRoot>/<berm.volume>` = `/run/berm/volumes/berm-example-app`.
   The mismatch left the app unpopulated even after fix 2. Fixed the mount path.

## No-store / no-log / no-plaintext-on-disk evidence

The harness's `phase_no_leak` captures this directly. For every known plaintext
value it runs, and asserts zero matches:

```
# daemon logs carry no secret value
docker logs berm-itest-daemon | grep -a -c -- "<value>"          -> 0  (for every value)

# the persisted ledger holds ciphertext hashes and names only, no value
docker run --rm -v berm-itest-state:/s <img> cat /s/ledger.json | grep -a -c -- "<value>"  -> 0
# and it is a real, non-empty ledger:
... | grep -a -c cipher_hash                                     -> > 0

# the daemon's writable layer (docker export excludes the read-only key and
# ciphertext mounts, so this is the container's own filesystem)
docker export berm-itest-daemon | grep -a -c -- "<value>"        -> 0  (for every value)

# the age secret key never appears inside any app container
docker export berm-itest-svca   | grep -a -c 'AGE-SECRET-KEY'    -> 0
docker export berm-itest-svcenv | grep -a -c 'AGE-SECRET-KEY'    -> 0

# the delivered secret sits ONLY on tmpfs
docker exec berm-itest-svca probe statfs /run/berm               -> tmpfs
```

In the most recent run every value grep returned 0 across the daemon log, the
ledger, and the daemon writable layer; the age key returned 0 in every app
container; and every delivery path statfs'd to tmpfs. This is the published
trust argument's empirical basis and is safe for docs/SECURITY to cite.
