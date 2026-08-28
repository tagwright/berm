# Empirical validation of the two gating claims

The berm architecture calls out two claims that gate the Docker one-shot-client
model and must be proven against reality rather than assumed. This document
records the question, the method, the evidence, and the conclusion for each,
with honest caveats. It is dated 2026-08-28 and was produced against a live
Docker on the build host.

Host under test:

- Docker Engine 29.1.3 (client 29.7.2), API 1.52
- containerd 2.2.1, runc 1.3.3
- Cgroup driver systemd, cgroup version 2

## Gate 1: Docker has no user-facing OCI hook

### Question

Does Docker / dockerd expose a user-facing, per-container OCI prestart /
createRuntime / createContainer hook mechanism the way Podman does (Podman
honors OCI hooks via `--hooks-dir` and the `hooks_dir` in containers.conf)? The
architecture INFERS Docker has none from documentation silence. The Podman
pre-start-hook delivery path depends on that contrast being real.

### Method

First-party inspection of the running Docker plus a documentation cross-check
for the Podman contrast. Concretely:

- `docker run --help` and `docker create --help`, grepped for any
  hook / prestart / createRuntime / OCI-hook flag.
- `dockerd --help` (via the `docker:29-dind` image), grepped for `hooks-dir`.
- `docker info` runtimes list.
- The Podman `oci-hooks(5)` documentation for what the contrast actually offers.

### Evidence

`docker run --help` and `docker create --help` carry NO hook-injection flag.
The only lines matching "OCI runtime" are unrelated:

```
--annotation map     Add an annotation to the container (passed through to the OCI runtime)
--runtime string     Runtime to use for this container
```

`--annotation` passes OCI annotations through and `--runtime` selects which OCI
runtime binary to use. Neither injects a hook. There is no `--hook`,
`--hooks-dir`, `--prestart`, or `--createruntime` flag.

`dockerd --help` has NO `hooks-dir` option (grep returned nothing).

`docker info` lists runtimes `io.containerd.runc.v2 runc` only.

By contrast, Podman's `oci-hooks(5)` documents a first-class, user-facing hook
mechanism: JSON hook definitions in `--hooks-dir` directories (defaulting to
`/usr/share/containers/oci/hooks.d` and `/etc/containers/oci/hooks.d`), with
`stages` including `precreate`, `prestart`, `createRuntime`, `createContainer`,
and `poststart`, and `when` conditions for label / annotation / command
matching. This is exactly the admission seam the berm Podman delivery path
uses, and it has no Docker equivalent.

The lower layers (runc, and the OCI runtime spec) DO support hooks in the
generated `config.json`, and runc's man page references the OCI spec's hooks.
But that `config.json` is produced by dockerd/containerd per container and is
not user-editable through any documented Docker CLI or Engine API surface.
There is no Docker-level, per-container way for an operator to register one.

### Conclusion

CONFIRMED (not refuted). Docker exposes no user-facing per-container OCI hook
mechanism. The claim holds. Docker's blast-radius-safe pre-start injection has
to be the one-shot client, because the clean pre-start admission hook exists
only on Podman.

Caveat, stated honestly: this is proven by the ABSENCE of a documented and
CLI/daemon-exposed mechanism, which is a negative. A private or undocumented
containerd/nri path is conceivable, but nothing user-facing exists, and NRI (a
containerd plugin interface) is a daemon-plugin surface, not a per-container
operator hook, so it does not change the delivery design.

Sources consulted for the Podman contrast:

- Podman oci-hooks(5): https://github.com/containers/podman/blob/v3.4.4/pkg/hooks/docs/oci-hooks.5.md
- Red Hat, OCI hooks for admission control in Podman: https://www.redhat.com/en/blog/open-container-initiative-hooks-admission-control-podman

## Gate 2: SO_PEERCRED resolves through the socket-bind-mount topology

### Question

When the berm daemon runs in a container and a DIFFERENT client container
connects to the daemon's unix socket (shared via a bind-mounted directory),
does SO_PEERCRED on the daemon side yield a pid that the daemon can resolve back
to the client container via `/proc/<pid>/cgroup`? SO_PEERCRED reports the peer
pid as seen in the READING process's pid namespace, so this hinges on the pid
namespace topology.

This is the critical gate: the peer authenticator's entire pid-to-container
walk depends on it. It was proven LIVE, not reasoned about.

### Method

A real harness (`test/peerauth/gate2/main.go`) running the SHIPPING code path:
it reads the raw SO_PEERCRED credential and then runs the real
`peerauth.Authenticate` walk (SO_PEERCRED to pid to `/proc/<pid>/cgroup` to
container id to `core.Inspect`) against the mounted Docker socket. Two sibling
containers were stood up, all named `berm-itest-*` and torn down on exit:

- a "daemon" container running `gate2 daemon`, with the shared dir and the
  Docker socket mounted, and
- a "client" container running `gate2 client`, with the shared dir mounted,
  connecting to the socket and holding the connection open.

Three topologies were tested to find the MINIMAL condition:

- A: daemon WITHOUT `--pid=host`, default cgroup namespace.
- B: daemon WITH `--pid=host`, default (private) cgroup namespace.
- C: daemon WITH `--pid=host` AND `--cgroupns=host`.

For each, the harness compared the daemon's resolved container id to the
client's real container id from `docker inspect`.

The runner is `test/peerauth/run-gate2.sh`.

### Evidence (observed pids and ids)

Scenario A, daemon in its own pid namespace:

```
GATE2 rawcred pid=0 uid=0 gid=0
GATE2 proc-cgroup pid=0 read error: open /proc/0/cgroup: no such file or directory
GATE2 RESULT: FAIL-CLOSED: peerauth: SO_PEERCRED returned no usable pid
VERDICT: DID NOT RESOLVE (fail-closed)
```

The peer is not visible in the daemon's pid namespace, so the kernel reports
pid 0. The authenticator fails closed, exactly as designed. It does NOT resolve.

Scenario B, daemon sharing the host pid namespace, default (private) cgroupns:

```
client real container id: cc908700c1a263a2c196ee9d544269064aabbeff18309d69f2955885ca8351b8
GATE2 rawcred pid=1733312 uid=0 gid=0
GATE2 proc-cgroup pid=1733312: "0::/../docker-cc908700c1a263a2c196ee9d544269064aabbeff18309d69f2955885ca8351b8.scope\n"
GATE2 RESULT: RESOLVED: {"container_id":"cc908700...","service":"berm-itest-gate2-client","peer_pid":1733312,...}
VERDICT: RESOLVED CORRECTLY (daemon id == client id)
```

Note the cgroup path shape: `0::/../docker-<id>.scope`. Because the daemon has
its own (private) cgroup namespace, the client's cgroup is shown RELATIVE to the
daemon's cgroupns root, hence the leading `/..`. The peerauth cgroup parser
handles this: it splits the path and extracts the id from any
`docker-<64hex>.scope` segment, so the relative `..` prefix is harmless. This
was a real-world shape that a naive "must start at /system.slice" parser would
have missed.

Scenario C, daemon sharing both the host pid and cgroup namespaces:

```
client real container id: 15c1c1281d5c1dd1272ad985acec60ffb2c253c6bc5166930b595d667a4667ae
GATE2 rawcred pid=1734204 uid=0 gid=0
GATE2 proc-cgroup pid=1734204: "0::/system.slice/docker-15c1c1281d5c1dd1272ad985acec60ffb2c253c6bc5166930b595d667a4667ae.scope\n"
GATE2 RESULT: RESOLVED: {"container_id":"15c1c128...","service":"berm-itest-gate2-client","peer_pid":1734204,...}
VERDICT: RESOLVED CORRECTLY (daemon id == client id)
```

With `--cgroupns=host` the path is the full absolute host form. Resolution is
identical and correct.

In both B and C the daemon resolved the SO_PEERCRED pid to the CORRECT client
container id (byte-equal to `docker inspect`), and the service identity fell
back to the container name as expected (the test containers carried no compose
service label and no `berm.name`).

### Conclusion

PROVEN LIVE, with a deployment requirement.

- SO_PEERCRED DOES resolve through the socket-bind-mount topology, but ONLY when
  the daemon container shares the host pid namespace (`--pid=host` /
  `pid: host`). Without it the peer pid is reported as 0 and the walk fails
  closed. This is now a documented deployment requirement for berm client-mode
  on Docker.
- `--cgroupns=host` is NOT required. Under the default private cgroup namespace
  the client's cgroup appears in the relative `/../docker-<id>.scope` form, and
  the peerauth parser extracts the id correctly. Running with the default
  cgroupns is therefore fine, which keeps the daemon's own cgroup isolation.
- The fail-closed behavior is not merely theoretical: scenario A demonstrates it
  live. A daemon deployed WITHOUT `pid: host` authenticates nobody rather than
  guessing, which is the safe failure.

Deployment requirement to carry into the client-mode docs and the shipped
compose snippet: the berm daemon container MUST run with `pid: host`. It may
keep the default cgroup namespace.

Caveats: proven on Docker 29 / cgroup v2 / systemd driver only. cgroup v1 and
the Podman rootful/rootless shapes are covered by the peerauth unit-test
fixtures but were not stood up as live sibling containers here (no Podman on the
build host). The Podman rootless case in particular should be re-proven live
when a Podman host is available, since its user-slice pid/cgroup topology
differs.
