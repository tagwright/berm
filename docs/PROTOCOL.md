# berm client-fetch wire protocol

The one-shot client (`berm-client`) and the daemon exchange a single
request/response over a local, peer-authenticated unix socket. The daemon
authenticates the caller from the socket's own `SO_PEERCRED`, resolves the
caller's plan, and returns exactly that caller's secrets. Secrets cross this
socket in plaintext. That is unavoidable and acceptable: the socket is local,
peer-authenticated, and the bytes never touch persistent disk on either side.

The protocol is implemented in `internal/wire`. It is length-prefixed and
versioned so it can evolve without a silent misparse.

## Framing

Every frame leads with two bytes:

```
byte 0   protocol version   (currently 1)
byte 1   message type
```

Message types:

| type | name             | direction        |
|------|------------------|------------------|
| 1    | fetch request    | client -> daemon |
| 2    | bundle response  | daemon -> client |
| 3    | error response   | daemon -> client |

All multi-byte integers are big-endian. Byte strings are length-prefixed: a
`u16` length for names, paths, owners, modes, and error text; a `u32` length for
secret payloads and the manifest. The decoder rejects any field longer than
64 MiB, so a corrupt or hostile length cannot drive an unbounded allocation.

A version mismatch on either side is a hard, loud error, never a best-effort
parse.

## Fetch request (type 1)

```
byte  version = 1
byte  type    = 1
```

No body. The daemon derives the caller's identity from the connection's peer
credentials, never from anything the client sends, so there is nothing to carry.

## Error response (type 3)

```
byte   version = 1
byte   type    = 3
u16    reasonLen
bytes  reason        (scrubbed, never a secret value)
```

## Bundle response (type 2)

```
byte   version = 1
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

- Daemon: `wire.ReadRequest`, then `delivery.BuildBundle(...)`, then
  `wire.EncodeBundle` (or `wire.WriteError`), then `bundle.Destroy()`. The
  secret bytes stream from their locked buffers straight onto the connection.
- Client: `wire.WriteRequest`, then `wire.ReadResponse`, which decodes secret
  payloads directly into fresh locked buffers. The client applies files and
  sets env, then `bundle.Destroy()` zeroizes every secret buffer (the exec form
  does this in the instant before `execve`).

## Versioning

The leading version byte is bumped whenever the frame layout changes. Bump
`wire.ProtocolVersion`, keep the old decoder path if backward compatibility is
wanted, and both ends reject a version they do not implement rather than
misread a secret.
