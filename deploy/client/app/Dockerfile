# SPDX-License-Identifier: GPL-3.0-or-later
#
# Example app image for client mode. It lifts berm-client straight out of the
# published berm image (a static binary, so no download, no checksum) and wraps
# its own entrypoint with it. berm-client fetches this container's secrets from
# the daemon, delivers them, and execs the real command in place.

FROM alpine:3.20

COPY --from=ghcr.io/tagwright/berm:00.01.00b1 /usr/local/bin/berm-client /usr/local/bin/berm-client

# Everything after the -- is the real application. Replace the CMD with your own
# process. berm-client execs it with the fetched secrets in place: files written
# to tmpfs and, when declared and acknowledged, env set in the exec environment.
ENTRYPOINT ["berm-client", "exec", "--"]
CMD ["sleep", "infinity"]
