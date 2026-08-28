# Berm

Label-driven secrets injection for Docker and Podman. Berm's daemon holds an
age key, decrypts SOPS- and age-encrypted sources, and hands each container only
the secrets it declared by label. You name the secrets in the compose file, next
to the service that needs them, and the values resolve at runtime. A label
carries a secret's name, never its value.

Berm does not reimplement crypto. SOPS and age do the decryption. Berm owns
discovery, the peer-authenticated fetch, and delivery, so a container obtains
only its own declared secrets, never the age key and never another container's.
It replaces the per-container `sops -d` that scatters plaintext and the age key
across a fleet with one daemon that holds one key, outside the containers.

Status: beta. The three delivery modes, the full label grammar, the CLI, and the
security contract are built and proven against a live Docker socket and a nested
Podman host. See [Status](#status).

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

The full label reference is in [docs/LABELS.md](docs/LABELS.md).

## Security contract

This is the spine of the tool, and the trust argument is the product. It is
stated in full, with the empirical evidence for each claim, in
[docs/SECURITY.md](docs/SECURITY.md).

Berm resolves and injects only. It never stores a secret, never logs a secret
value, and never writes plaintext to persistent disk. Plaintext lives in tmpfs
and locked memory. The age key lives only with the daemon and never inside any
container. A compromised container can reach only its own declared secrets: it
cannot obtain the age key, and it cannot obtain another container's secrets.
There is no read-back API. Identity is proven by the kernel (`SO_PEERCRED` walked
to the caller's container), not asserted by the caller.

The beta version scheme is a deliberate trust posture for a secrets daemon, not
a signal of an unfinished tool.

## Delivery

Files are the secure default. A secret at a tmpfs path with a tight owner and
mode is not visible in `docker inspect` and not visible to other users on the
host. Three mechanisms deliver it, chosen with `berm.delivery`:

- `client` (Docker default): a one-shot `berm-client` wrapper in the container
  entrypoint fetches over the peer-authenticated socket and execs the app with
  the secrets in place. The only mode that can deliver env.
- `hook` (Podman default): an OCI pre-start hook writes files into the
  container's own mount namespace before PID 1. No image change. Files only.
- `volume` (both runtimes): a tmpfs-backed named volume plus a waiter that closes
  the container-start race. No image change. Files only.

The default is `BERM_DEFAULT_DELIVERY`, which itself defaults per runtime (Docker
`client`, Podman `hook`).

Environment-variable delivery is opt-in and the exposed exception. It is
delivered only through the client wrapper, refused in hook and volume modes, and
gated behind a per-container `berm.env.acknowledge=true` on top of the
declaration, because a value in the environment is readable via
`/proc/<pid>/environ` from inside the container and by host root, which a file at
mode `0400` owned by the app user is not.

## Both runtimes

Berm talks to Docker and Podman through the same shared runtime the rest of the
suite uses, pointed at whichever socket is mounted. Set `BERM_RUNTIME=podman` (or
leave it unset for Docker). The per-runtime delivery default differs. The label
grammar does not. The three modes and their corrected deploy recipes are in
[docs/OPERATIONS.md](docs/OPERATIONS.md) and the runnable
[deploy/](deploy/) examples.

## Quick start

This walks the canonical case: one secret delivered to a file in client mode on
Docker. The runnable version is [deploy/client](deploy/client).

### 1. Set up SOPS with age

Generate an age key. Keep the private key off the host it protects:

```sh
age-keygen -o berm-age-key.txt
```

That prints the matching public key (`age1...`) to stderr. Point SOPS at it with
a `.sops.yaml` next to your source files, so `sops` knows who can decrypt them:

```yaml
creation_rules:
  - path_regex: \.sops\.env$
    age: age1exampleexampleexampleexampleexampleexampleexampleexamplex
```

Write the service's secrets as `KEY=value` pairs and encrypt the file in place.
The `KEY` names are the same names your labels reference:

```sh
printf 'POSTGRES_PASSWORD=%s\n' "$(openssl rand -base64 24)" > example-app.sops.env
sops -e -i example-app.sops.env
```

`example-app.sops.env` now holds ciphertext (each value as `ENC[...]`, each key
in cleartext) and is safe to commit.

### 2. Write berm.yml

`berm.yml` holds structure, not secrets, so it is safe to commit. It names the
source, its format, and which age key unseals it. See
[berm.example.yml](berm.example.yml).

```yaml
age_keys:
  default: /run/berm/age/default.key

sources:
  example-app:
    file: example-app.sops.env    # relative, resolved under BERM_SOURCES_ROOT
    format: dotenv                # dotenv (default) or binary
```

### 3. Deploy the daemon

The daemon mounts the container socket (read-only), the encrypted sources
(read-only), and the age key (read-only, daemon only). It runs with `pid: host`
so it can authenticate callers by their socket peer credential, and with
`network_mode: none` because it never phones out. Provision the age key with SOPS
at deploy time and never commit the decrypted key:

```sh
mkdir -p ./secrets/age
sops -d berm-age-key.txt.sops > ./secrets/age/default.key
chmod 0400 ./secrets/age/default.key
```

The full client-mode compose is [deploy/client/docker-compose.yml](deploy/client/docker-compose.yml).
Its app image lifts `berm-client` out of the published image and wraps its own
entrypoint with `berm-client exec -- <app>`.

### 4. Verify it worked

```sh
# The manifest resolves cleanly and no container has a validation error:
berm validate

# Each enabled container's delivery targets, injection state, and any warnings:
berm status

# The secret is on the app's tmpfs, byte-for-byte:
docker exec example-app cat /run/berm/pgpass

# and it is ABSENT from inspect (a file secret never enters the container config):
docker inspect example-app | grep -c POSTGRES_PASSWORD   # the value: 0
```

`berm validate` exits nonzero when any container fails validation, so it works as
a pre-deploy CI gate. Migrating an existing service? `berm suggest <service>`
reads only the cleartext key names from its existing sops file (it never runs
`sops -d`) and prints ready-to-paste labels and a `berm.yml` stanza.

## Documentation

- [docs/LABELS.md](docs/LABELS.md): every label, the ref grammar, scoping, and
  worked examples.
- [docs/OPERATIONS.md](docs/OPERATIONS.md): the three deploy modes, rotation by
  recreate, the CLI workflows, and the `BERM_*` globals.
- [docs/SECURITY.md](docs/SECURITY.md): the full security contract, the secret
  handling, the honest threat model, and the empirical evidence.
- [docs/TESTING.md](docs/TESTING.md): what is proven live, compile-only, and
  unproven, and the bugs the integration campaign found.
- [docs/PROTOCOL.md](docs/PROTOCOL.md): the wire protocol.
- [docs/EMPIRICAL.md](docs/EMPIRICAL.md): the two gating claims, proven live.

## Status

Berm is built and running. The three delivery modes (client, hook, volume), the
full label grammar, the SOPS/age backend, the peer authenticator, the CLI
(`daemon`, `status`, `stale`, `validate`, `suggest`, `version`), and the security
contract all work end to end. What is honestly not proven yet:

- Rootless Podman end to end. The rootful hook path is fully proven live. The
  fully-rootless daemon-plus-hook chain is not yet stood up. See
  [docs/TESTING.md](docs/TESTING.md).
- cgroup v1 is covered by unit fixtures only. The live proof is cgroup v2.
- SOPS/age is the only backend. The backend seam is designed to hold a second
  one, but nothing else implements it yet.

App-specific hashing (qbittorrent PBKDF2, bazarr MD5) and config-file templating
(ntfy, node-red) are out of scope: berm delivers plaintext to a path. Pin a
version if you build on it. The label grammar can still change before a 1.0.

## License

GPL-3.0-or-later. You can run it, charge for it, and modify it. If you distribute
a modified version, it stays open under the same license. Each source file
carries an `SPDX-License-Identifier: GPL-3.0-or-later` header. See
[LICENSE](LICENSE).
