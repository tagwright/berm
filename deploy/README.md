<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# berm deploy examples

Runnable, honest compose examples for the three delivery modes. Each stands up
the berm daemon plus the consumer-side plumbing that mode needs. Adjust the image
tag, paths, and source names to your fleet.

The daemon image is `ghcr.io/tagwright/berm:00.01.00b1`. The tag matches the
binary's `berm version`.

## What every mode has in common

- **The age key lives only with the daemon.** It is mounted read-only into the
  berm service and into no app container. A compromised app can never obtain the
  key, only its own declared secrets.
- **No daemon network egress.** The daemon reads local ciphertext and a local key
  and never phones out, so the examples give it `network_mode: none`. That is the
  strongest statement of the security contract's no-egress rule. The distroless
  image carries no shell and no network tooling, and the runtime setting is what
  actually removes the route out. If you later wire beacon push telemetry to a
  local collector, swap `network_mode: none` for an internal (`internal: true`,
  gateway-less) network that reaches only that collector.
- **`pid: host` on the daemon.** The daemon authenticates a caller by its socket
  peer credential and walks `/proc` in the host PID namespace (SO_PEERCRED to PID
  to cgroup to container id). That resolution only works in the host PID
  namespace, so client and hook mode both need `pid: host` on the daemon.
- **`berm.yml` is structure, not secrets.** It holds names, paths, formats,
  owners, and grants, so it is safe to commit. The examples reuse the repo's
  [`berm.example.yml`](../berm.example.yml). Copy it in as `berm.yml` and edit.
- **Secrets are ciphertext at rest.** The `*.sops.env` and `*.sops.bin` files
  under `BERM_SOURCES_ROOT` are age-encrypted and mounted read-only.

## Provisioning the age key with SOPS at deploy time

The daemon needs the plaintext age key file at the path `berm.yml` names (the
examples use `/run/berm/age/default.key`). Keep the key age-encrypted at rest and
decrypt it into place in your deploy step, exactly the way the rest of the suite
provisions a daemon's key. For example, in a deploy script:

```sh
mkdir -p ./secrets/age
sops -d age-default.key.sops > ./secrets/age/default.key
chmod 0400 ./secrets/age/default.key
```

Never commit the decrypted key. The examples mount `./secrets/age` read-only into
the daemon only. The `.gitignore` already excludes `*.key`.

## The three modes

| Mode | Runtime primary | Consumer plumbing | Env-capable |
|---|---|---|---|
| [`client/`](client/) | Docker | `berm-client exec -- <app>` entrypoint, socket shared to app | yes (double-gated) |
| [`hook/`](hook/) | Podman | OCI pre-start hook installed on the host | no |
| [`volume/`](volume/) | both | tmpfs named volume plus a waiter service | no |

Env delivery is refused outright in hook and volume mode, because neither can
control the process environment: a silent no-op there would be worse than an
error. Env is client-mode only, and even there it needs the second explicit
`berm.env.acknowledge=true` per container.
