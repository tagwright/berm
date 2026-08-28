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

Then make sure Podman actually scans that directory. On current Podman
(verified against 5.8) the built-in `hooks_dir` default does not reliably
include `/etc/containers/oci/hooks.d`, so set it explicitly in
`containers.conf`:

```sh
sudo mkdir -p /etc/containers
printf '[engine]\nhooks_dir = ["/etc/containers/oci/hooks.d"]\n' \
  | sudo tee -a /etc/containers/containers.conf
```

The `when.annotations` match fires the hook only for containers carrying the
`berm.enable=true` OCI **annotation**, and the `createContainer` stage runs the
hook inside the container's own mount namespace after the container's mounts (the
tmpfs the secret lands on) are set up but before `pivot_root` and before PID 1,
which is when `berm-hook` writes the secret files under the container rootfs the
OCI state names. The keys and values in `when.annotations` are regexes, hence the
`^...$` anchors.

The trigger is an OCI **annotation**, not a label: on current Podman a container
label is NOT surfaced as an OCI annotation, so set the trigger with
`--annotation berm.enable=true` (`podman run`) or the compose `annotations:`
block. The berm **labels** the daemon reads for delivery (`berm.enable`,
`berm.name`, `berm.file.*`, and so on) are separate and set as labels as usual, so
a hook-mode container carries `berm.enable` in both places: as an annotation for
the trigger and as a label (with the rest of the `berm.*` config) for the daemon.

The hook connects to the daemon at its default socket `/run/berm/berm.sock`,
which the daemon service below binds to a host path, so the host-side hook can
reach it (at the createContainer stage the hook's `/` is still the host root, so
this host path resolves). No hook env is needed.

## The daemon service

See [`podman-compose.yml`](podman-compose.yml). Run it with `podman-compose` (or
translate to a quadlet/systemd unit). For a rootless Podman host, use the
rootless socket path noted in the file and confirm the write-into-own-mount-
namespace path works without privilege for your setup, which is the one hook-mode
item the architecture flags to prove per host.
