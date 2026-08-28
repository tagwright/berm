# Testing

berm is tested at two levels: the Go unit and library tests that ship with each
package, and a real integration harness that drives the actual daemon image
against live Docker containers over the real Docker socket. This document records
what is proven, what is compile-only, and what is unproven, honestly.

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

### Coverage: COMPILE-ONLY / UNPROVEN

- Podman (hook mode and the rootless nested-podman path) is NOT exercised here.
  The hook handler and the OCI pre-start hook are unit-tested, and the peerauth
  fixtures cover Podman cgroup shapes, but no live Podman host was driven. This
  is a separate later chunk (9b).
- cgroup v1 and the Podman rootful/rootless SO_PEERCRED topologies are covered
  by peerauth unit fixtures only; the live proof is Docker 29 / cgroup v2 /
  systemd (see EMPIRICAL.md).

## Bugs found and fixed by the integration pass

Every integration pass in this suite has found at least one real bug. This one
found three, all in paths unit tests could not reach:

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
