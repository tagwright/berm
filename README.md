# Berm

Label-driven secrets injection for Docker and Podman. Berm's daemon holds an
age key, decrypts SOPS- and age-encrypted sources, and hands each container
only the secrets it declared by label. You name the secrets in the compose
file, next to the service that needs them, and the values resolve at runtime.
A label carries a secret's name, never its value.

Berm does not reimplement crypto. SOPS and age do the decryption. Berm owns
discovery, the peer-authenticated fetch, and delivery, so a container obtains
only its own declared secrets, never the age key and never another container's.
It replaces the per-container `sops -d` that scatters plaintext and keys across
a fleet with one daemon that holds one key, outside the containers.

Status: scaffolding. This repo currently holds the module layout, the license,
and the interface seams. The commands print "not implemented". See
[Status](#status) for what is here and what is not.

## The idea

A container declares which secrets it needs and where they should land:

```yaml
services:
  firefly-db:
    image: postgres:16
    labels:
      berm.enable: "true"
      berm.file.pgpass.from: "POSTGRES_PASSWORD"
```

The default source is the service name, `firefly-db`. The `POSTGRES_PASSWORD`
key from that source lands at `/run/berm/pgpass`, tmpfs-backed, owned by the
container's user, mode `0400`. Because `POSTGRES_PASSWORD_FILE` is a recognized
`_FILE` pointer, that non-secret env var is set to the path, and postgres reads
its password from the file with nothing exposed in `docker inspect`.

The full label grammar is frozen. It covers file, env, and whole-source
deliveries, cross-service grants, and the delivery mechanism. A later chunk
ships it as `docs/LABELS.md`.

## Security contract

Berm resolves and injects only. It never stores a secret, never logs a secret
value, and never writes plaintext to persistent disk. Plaintext lives in tmpfs
and memory. The age key lives only with the daemon and never inside any
container. A compromised container can reach only its own declared secrets: it
cannot obtain the age key, and it cannot obtain another container's secrets.
There is no read-back API.

The beta version scheme is a deliberate trust posture for a secrets daemon, not
a signal of an unfinished tool.

## Delivery

Files are the secure default. A secret at a tmpfs path with a tight owner and
mode is not visible in `docker inspect` and not visible to other users on the
host. Three mechanisms deliver it:

- `client`: a one-shot `berm-client` wrapper in the container entrypoint fetches
  over the peer-authenticated socket and execs the app with the secrets in
  place. This is the Docker default and the only mode that can deliver env.
- `hook`: an OCI pre-start hook writes files into the container's mount
  namespace before the process starts. This is the Podman default. Files only.
- `volume`: a tmpfs-backed named volume plus a waiter that closes the
  container-start race. Both runtimes, no image change. Files only.

Environment-variable delivery is opt-in and the exposed exception. It is
delivered only through the client wrapper, refused in hook and volume modes, and
gated behind a per-container acknowledgment on top of the declaration, because a
value in the environment is readable from inside the container and by host root.

## Both runtimes

Berm talks to Docker and Podman through the same shared runtime the rest of the
suite uses, pointed at whichever Docker-compatible socket is mounted. The
per-runtime delivery default differs (Docker `client`, Podman `hook`); the label
grammar does not.

## Secrets with SOPS

The daemon reads ciphertext under `BERM_SOURCES_ROOT` and an age key mounted by
path. Both come from the host at deploy time, the same SOPS-provisioned way the
rest of the homelab gets its secrets. The key never enters a consumer container.
`berm.yml` holds the source names, formats, owners, and grants, and nothing in
it is a secret value, so it is safe to commit. See
[berm.example.yml](berm.example.yml).

## Status

Nothing is wired up yet. This scaffold contains:

- The Go module, the GPLv3 license, and an SPDX header on every source file.
- The backend seam (`internal/backend`) with the SOPS/age driver stubbed. The
  seam is phrased in berm's own nouns so a second backend can slot in later.
- The delivery seam (`internal/delivery`) over the three mechanisms, with the
  env-exposure gate expressed on it.
- The berm.yml schema and loader (`internal/config`).
- The parsed label model (`internal/label`), types only, no parser yet.
- The CLI skeleton (`berm` and `berm-client`), commands stubbed.

Later chunks fill the daemon, the resolver and peer authenticator, the SOPS/age
driver, the three delivery mechanisms, and the integration harness.

## License

GPL-3.0-or-later. You can run it, charge for it, and modify it. If you
distribute a modified version, it stays open under the same license. Each source
file carries an `SPDX-License-Identifier: GPL-3.0-or-later` header. See
[LICENSE](LICENSE).
