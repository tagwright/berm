<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Security

For a secrets tool the trust argument is the product, so this document is a
deliverable, not an afterthought. It states the contract in full, explains how the
code holds it, cites the live evidence, and is honest about what it does not
defend against. Every claim here is checkable against the code and the integration
harness in [TESTING.md](TESTING.md).

## The contract

Berm resolves and injects secrets. It does nothing else with them.

- It never **stores** a secret. There is no datastore and no read-back API. The
  only state at rest is a ciphertext-hash ledger for staleness, which holds hashes
  and names, never a value.
- It never **logs** a secret value. Diagnostics name containers, sources, refs,
  and reasons only. The whole error taxonomy is built to carry structured fields
  that are never a value.
- It never writes **plaintext to persistent disk**. Delivered secrets land on
  tmpfs, and the daemon refuses a non-tmpfs destination. The transient plaintext
  window during a resolve lives in locked memory.
- The **age key lives only with the daemon** and never inside any container.
- A compromised container can reach **only its own declared secrets**. It cannot
  obtain the age key, and it cannot obtain another container's secrets.

## The upgrade over the status quo

The status quo this replaces is per-container `sops -d`: every container that
needs a secret carries the age key and runs the decrypt itself. That scatters the
one key that unlocks everything across the whole fleet, and scatters plaintext
into whatever each container does with it. The blast radius of any one compromised
container is the entire secret store, because the key is right there.

Berm holds one key, in one place, outside every container. A container never sees
the key. It fetches only the specific secrets it declared, and it proves who it is
to the kernel rather than asserting an identity berm has to trust. The blast radius
of a compromised container shrinks from the whole store to that one container's own
declared secrets.

## How the plaintext window is handled

Berm drives the `sops` binary as a subprocess to decrypt a source, and never
reimplements crypto. The age key never enters the berm process: `sops` reads the
key file itself from a `SOPS_AGE_KEY_FILE` path in a minimal subprocess
environment, and berm holds only the path, never the key material, and never passes
it on argv. Plaintext is handled to keep its window as narrow as the source's shape
allows, and the code is honest that not every path can be fully off-heap:

- **Binary whole-payload delivery is fully off-heap.** `sops`'s stdout is wired
  straight to the destination file descriptor, so the payload flows kernel-pipe to
  the tmpfs file and never enters a Go buffer or the managed heap at all. This is
  the preferred path and the one a binary source and a whole-source file delivery
  take.
- **Extracting one dotenv key necessarily transits locked memory.** Finding one
  `KEY` in a dotenv payload requires parsing it, so that path pulls the
  whole-source plaintext into a memguard `LockedBuffer`, held in locked,
  non-swappable memory. The one value is copied out into its own locked buffer, and
  the whole-source buffer is destroyed the instant the value is copied, so the rest
  of the source's plaintext lives for the shortest possible window. The doc does not
  claim this path is off-heap, because it is not: it is locked memory, which is the
  honest best available for a parse.
- **Secrets are `[]byte`, never `string`.** A Go `string` is immutable and cannot
  be zeroized. A `[]byte` in a locked buffer can. No secret value is ever converted
  to a string.
- **Best-effort zeroize.** Every locked buffer a decrypt retains to back a returned
  value is destroyed when the caller is done (on the handle's `Close`, and on the
  client the bundle's `Destroy` runs in the instant before `execve`). This is
  best-effort by nature (an OS can always have paged or copied a page before it was
  locked), stated plainly rather than sold as a guarantee.

## Per-container blast-radius scoping

Two independent mechanisms contain what a container can obtain. Both hold
regardless of the `berm.yml` grants.

**Kernel-attested peer authentication (client mode).** When a container's
`berm-client` connects to the daemon socket, the daemon does not trust anything the
client sends. It reads the connection's `SO_PEERCRED`, a credential the kernel
attaches to the socket, to learn the caller's PID, then walks `/proc/<pid>/cgroup`
to the caller's container id, then to that container's labels. The client presents
no id at all, so it cannot ask for another container's secrets: identity is proven
by the kernel, not asserted by the caller. The walk is pinned by process start time
to defeat PID reuse (a PID recycled to a different process resolves to a mismatch
and fails, rather than being mistaken for the original). If the peer PID cannot be
resolved, the daemon fails closed and authenticates nobody.

**Manifest scoping.** Whatever the mechanism, the daemon resolves exactly the
declared plan for one container and delivers exactly that. Env and pointers are
expanded server-side, and whole-source renders are expanded into ordinary file entries
before the bundle is even encoded. A container receives its own declared bundle and
nothing else.

**Hook mode's trust model** is different by necessity and stated as such. A
pre-start hook has no peer container identity of its own, so `berm-hook` presents
the container id and the container's own OCI annotations (its `berm.*` config, which
the runtime hands the hook in the OCI state). The daemon does not deliver blindly:
it derives the service identity, confirms the container is berm-enabled, and
resolves the presented config against `berm.yml` (source existence, ref shape,
owner plus grants, files-only). The hook is a trusted, privileged host-side injector
the operator installs, so the trust boundary is the operator's control of the host,
which is where it already sits.

## The evidence

These are not assertions. The integration harness proves them live against real
containers, and the greps are reproduced in [TESTING.md](TESTING.md).

- **No value in the daemon logs, the ledger, or the daemon's writable layer.** For
  every known plaintext value, after a full injection cycle, `grep -c` over the
  daemon logs, the persisted ledger, and the daemon's `docker export` returns `0`.
  The ledger is real and non-empty (it has `cipher_hash` entries), it just holds no
  value.
- **The age key never reaches an app container.** `docker export` of every app
  container greps `0` for `AGE-SECRET-KEY`.
- **Delivery is on tmpfs only.** Every delivery path `statfs`'s to tmpfs.
- **Peer-auth isolation is adversarial-tested.** Container A receives only its own
  secret and never B's, and vice versa. An ungranted cross-service read is refused
  fail-closed (the client exits nonzero, no value delivered), classified
  `ungranted_ref`, and stays sticky in the digest while the rest of the fleet is
  still served.
- **The fail-closed peer-auth is demonstrated, not reasoned about.** A daemon
  deployed without `pid: host` resolves the peer PID as `0` and authenticates
  nobody. See [EMPIRICAL.md](EMPIRICAL.md).

## The honest threat model

The `berm.yml` owner-plus-grant scoping catches operator **mistakes**: copy-paste
drift, an over-broad `access:` list, a consumer reaching for a source it should not.
It does **not** defend against a malicious operator. Whoever writes the compose
files is the operator, and an operator can mount anything anyway, so grants are an
audit and mistake-catching layer, not a boundary against the person who controls
the deployment.

The boundary that does hold against a compromised **container** is the runtime
guarantee: kernel-attested peer authentication of the fetching container plus
manifest scoping of what it receives. That holds regardless of what the grants say.
Grants make `berm.yml` the single audited answer to who can read what. Peer auth
makes the answer enforceable against a container that lies.

### The `pid: host` trade-off

Client-mode and hook-mode peer authentication need the daemon in the host PID
namespace (`pid: host`), because `SO_PEERCRED` reports the peer PID as seen in the
reading process's PID namespace and the `/proc` walk only resolves there. This is a
real trade-off, stated plainly: `pid: host` widens the daemon's view of host
processes. It is inherent to the `SO_PEERCRED` technique, not a shortcut. The daemon
is otherwise hardened to shrink what that widened view is worth to an attacker who
compromised it: distroless with no shell, no network egress (`network_mode: none`),
optionally a read-only rootfs and `no-new-privileges`, and a plaintext window that
is memory-only. `--cgroupns=host` is not required, so the daemon keeps its own
cgroup isolation.

## Recovery

- **Back up the age key and the SOPS master material off-host, durably.** The age
  key is the one thing that unlocks every source. Losing it loses every secret,
  and leaking it loses the contract. Keep it encrypted at rest and provisioned into the
  daemon only at deploy time, and keep a durable off-host copy of both the age key
  and whatever SOPS master material your setup uses.
- **Rotate by recreate.** Edit and re-encrypt the source, then recreate the
  affected container (`docker compose up -d --no-deps <service>`, or the Podman
  equivalent). The one-shot client and the hook deliver only at start, so a rotated
  secret reaches a running container on recreate. This is the same
  recreate-to-pick-up-new-secrets discipline the rest of the homelab uses.
- **A renamed or deleted source surfaces, it never silently empties.** Referencing
  a source not in `berm.yml` is a sticky `missing_source` error, and a source
  deleted after injection surfaces in `berm stale` as loudly as a changed one. The
  convention never resolves to nothing.

## Known limitations

Stated honestly, so nobody deploys expecting a guarantee that is not there.

- **Rootless Podman end to end is unproven.** The rootful hook path is fully proven
  live. The `createContainer` hook is observed to fire under rootless Podman and the
  write path applies unchanged, but the fully-rootless daemon-plus-hook chain (a
  user-owned socket, a rootless age-key chain) was out of scope for the harness and
  is not yet stood up. Its user-slice pid/cgroup topology differs and should be
  re-proven live on a real rootless host. See [TESTING.md](TESTING.md).
- **cgroup v1 is unit-fixture only.** The live proof is cgroup v2 (Docker 29 /
  systemd, and Podman 5.8 / crun / cgroup v2). cgroup v1's peerauth parsing is
  covered by unit fixtures, not a live sibling-container run.
- **App-specific hashing is out of scope.** Berm delivers plaintext to a path. Apps
  that want a hashed credential (qbittorrent PBKDF2, bazarr MD5) are not served: a
  file-capable app that needs the secret pre-hashed is the app-specific coupling the
  suite refuses to embed. This is a real edge, named here, not a residual that does
  not apply.
- **Config-file templating is cut from v1.** Apps that want a secret pasted into a
  mixed config file (ntfy, node-red) are out of scope. A future `templates` block in
  `berm.yml` could serve the config-embed case additively, without changing the
  no-hashing stance for the general path.
- **DoH-style residuals do not apply here.** Berm is not a network egress tool, so
  the DNS-over-HTTPS and direct-IP residuals that qualify an FQDN egress policy are
  irrelevant to it. It is named only to be explicit that it was considered and does
  not apply. The app-specific-hashing edge above is the one that does.
