<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Hook mode (Podman primary)

An OCI pre-start hook writes each berm-enabled container's secret files into the
container's own mount namespace before PID 1. There is no client binary in the
app image, no entrypoint change, and no start race. Files only: env is refused
end to end in hook mode.

## Install the hook binary on the host

`berm-hook` is a host-side component. Lift it out of the published image (or take
it from a release asset) and place it on the host:

```sh
# From the image:
id=$(sudo podman create ghcr.io/tagwright/berm:00.01.00b1)
sudo podman cp "$id":/usr/local/bin/berm-hook /usr/local/bin/berm-hook
sudo podman rm "$id"
sudo chmod 0755 /usr/local/bin/berm-hook
```

## Install the hook definition

Copy [`hooks.d/berm-hook.json`](hooks.d/berm-hook.json) into Podman's hooks
directory:

```sh
sudo install -D -m 0644 hooks.d/berm-hook.json \
  /etc/containers/oci/hooks.d/berm-hook.json
```

The `when.annotations` match fires the hook only for containers carrying the
`berm.enable=true` annotation, and the `createRuntime` stage runs it after the
runtime namespaces exist but before the container process starts, which is when
`berm-hook` writes into `/proc/<pid>/root` in the container's mount namespace.
Under Podman a container label surfaces as an OCI annotation of the same key, so
a `berm.enable: "true"` label (compose) or `--annotation berm.enable=true`
(`podman run`) both trigger it. The keys and values in `when.annotations` are
regexes, hence the `^...$` anchors.

The hook connects to the daemon at its default socket `/run/berm/berm.sock`,
which the daemon service below binds to a host path, so the host-side hook can
reach it. No hook env is needed.

## The daemon service

See [`podman-compose.yml`](podman-compose.yml). Run it with `podman-compose` (or
translate to a quadlet/systemd unit). For a rootless Podman host, use the
rootless socket path noted in the file and confirm the write-into-own-mount-
namespace path works without privilege for your setup, which is the one hook-mode
item the architecture flags to prove per host.
