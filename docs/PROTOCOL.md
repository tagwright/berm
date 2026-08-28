# berm wire protocol

The consumers (`berm-client` and `berm-hook`) and the daemon exchange a single
request/response over a local unix socket. Secrets cross this socket in
plaintext. That is unavoidable and acceptable: the socket is local, the request
is trusted or peer-authenticated per the two request types below, and the bytes
never touch persistent disk on either side.

There are two request types, with two deliberately different trust models:

- The **fetch request** (client mode) carries no body. The daemon derives the
  caller's identity from the socket's own kernel-attested `SO_PEERCRED`, walks it
  to the caller's container, resolves that container's plan, and returns exactly
  its secrets. A client cannot ask for another container's secrets, because it
  presents no id at all: identity is proven by the kernel, not asserted by the
  client.
- The **hook request** (hook mode) carries an OCI container id AND the
  container's OCI annotations. It comes from the OCI pre-start hook, a trusted,
  privileged host-side injector the operator installs via Podman's `hooks_dir`.
  The hook has no peer container identity of its own, so it presents the id and
  the container's own config annotations (the `berm.*` keys the runtime handed it
  in the OCI state). The daemon resolves from those presented annotations rather
  than inspecting the container over the runtime API: the pre-start hook fires
  while the runtime holds the container-creation lock, so a daemon Inspect of that
  same container would deadlock against the create the hook is blocking (this was
  found live in the nested-podman integration pass). The daemon still validates
  rather than delivers blindly: it derives the service identity, confirms the
  container is berm-enabled, and resolves the presented config against `berm.yml`
  (source existence, ref shape, owner-plus-grant scoping, files-only). Client =
  kernel-attested peer identity; hook = trusted privileged injector presenting the
  container's own config, which the daemon then validates against `berm.yml`.

The protocol is implemented in `internal/wire`. It is length-prefixed and
versioned so it can evolve without a silent misparse.

## Framing

Every frame leads with two bytes:

```
byte 0   protocol version   (currently 2)
byte 1   message type
```

Message types:

| type | name             | direction        |
|------|------------------|------------------|
| 1    | fetch request    | client -> daemon |
| 2    | bundle response  | daemon -> consumer |
| 3    | error response   | daemon -> consumer |
| 4    | hook request     | hook   -> daemon |

All multi-byte integers are big-endian. Byte strings are length-prefixed: a
`u16` length for names, paths, owners, modes, error text, and the hook's
container id; a `u32` length for secret payloads and the manifest. The decoder
rejects any field longer than 64 MiB, so a corrupt or hostile length cannot
drive an unbounded allocation.

A version mismatch on either side is a hard, loud error, never a best-effort
parse. The daemon reads the header with `wire.ReadRequestHeader`, which returns
the request type, and dispatches: a fetch request runs the peer-auth path (no
more bytes to read), a hook request is followed by `wire.ReadHookBody` for the
container id.

## Fetch request (type 1)

```
byte  version = 2
byte  type    = 1
```

No body. The daemon derives the caller's identity from the connection's peer
credentials, never from anything the client sends, so there is nothing to carry.

## Hook request (type 4)

```
byte   version = 2
byte   type    = 4
u16    idLen
bytes  containerID   (the OCI container id from the runtime state JSON)
u16    nAnnotations
repeat nAnnotations (keys sorted, so the frame is deterministic):
    u16   keyLen;   bytes key
    u16   valLen;   bytes value
```

Neither the container id nor the annotations are secret. The daemon resolves the
plan from the presented annotations (the container's own `berm.*` config) WITHOUT
inspecting the container over the runtime API, because the pre-start hook fires
while the runtime holds the container-creation lock and a daemon Inspect of that
same container would deadlock against the create the hook is blocking. The daemon
derives the service identity from the annotations (`berm.name`, else a
compose-service annotation; there is no container name to fall back on in hook
mode), confirms the container is berm-enabled, resolves its plan, refuses any env
(hook mode is files only), and returns its file bundle. A hook request for a
container that is not berm-enabled, or whose resolved mechanism is not `hook`, is
refused.

## Error response (type 3)

```
byte   version = 2
byte   type    = 3
u16    reasonLen
bytes  reason        (scrubbed, never a secret value)
```

## Bundle response (type 2)

```
byte   version = 2
byte   type    = 2

u32    nFiles
repeat nFiles:
    u16   pathLen;   bytes path
    u16   ownerLen;  bytes owner    ("uid" or "uid:gid", numeric)
    u16   modeLen;   bytes mode     (octal string, e.g. "0400")
    u32   dataLen;   bytes data     (SECRET plaintext)

u32    nEnv
repeat nEnv:
    u16   nameLen;   bytes name
    u32   valLen;    bytes value    (SECRET plaintext)

u32    nPointers
repeat nPointers:
    u16   nameLen;   bytes name     (e.g. "POSTGRES_PASSWORD_FILE")
    u16   pathLen;   bytes path     (NOT a secret; a tmpfs path)

u32    manifestLen
bytes  manifest                     (NOT a secret; names/paths/hashes only)
```

Whole-source renders (`berm.dotenv`, `berm.envdir`) are expanded by the daemon
into ordinary file entries before encoding: a dotenv render is one file of
`KEY=VALUE` lines, an envdir render is one file per key under the directory. The
client writes files and sets env and needs no render logic.

Env entries and pointers appear only in client mode. In file-only modes (hook,
volume) the daemon writes files itself and records any `_FILE` pointer in the
manifest instead of setting it.

## Handling on each side

- Daemon: `wire.ReadRequestHeader` to learn the request type, then either the
  peer-auth path (fetch) with `delivery.BuildBundle(...)`, or `wire.ReadHookBody`
  plus `hookd.Handler.Handle(...)` (hook). Then `wire.EncodeBundle` (or
  `wire.WriteError`), then `bundle.Destroy()`. The secret bytes stream from their
  locked buffers straight onto the connection.
- Client: `wire.WriteRequest`, then `wire.ReadResponse`, which decodes secret
  payloads directly into fresh locked buffers. The client applies files and
  sets env, then `bundle.Destroy()` zeroizes every secret buffer (the exec form
  does this in the instant before `execve`).
- Hook (`berm-hook`): parse the OCI state from stdin, `wire.WriteHookRequest`
  with the container id and the state's annotations, then `wire.ReadResponse`. It
  writes the bundle's files into the container's own mount namespace before PID 1
  (under the container rootfs at the createContainer stage) and `bundle.Destroy()`s.
  A hook bundle carries files and a manifest only, never env.

## Versioning

The leading version byte is bumped whenever the frame layout changes. Version 2
added the hook request (type 4). Bump `wire.ProtocolVersion`, keep the old
decoder path if backward compatibility is wanted, and both ends reject a version
they do not implement rather than misread a secret.
