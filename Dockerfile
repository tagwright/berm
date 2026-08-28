# SPDX-License-Identifier: GPL-3.0-or-later
#
# berm daemon image. Multi-stage: a golang build stage compiles the three
# binaries and fetches the pinned sops backend, a distroless final stage carries
# only the daemon, sops, and the two consumer-side binaries. The final image has
# no shell, no package manager, and no network tooling.
#
# Build from the berm repository root:
#
#   docker build -t ghcr.io/tagwright/berm:dev .
#
# core and beacon are consumed as published modules (github.com/tagwright/core,
# github.com/tagwright/beacon). GOPRIVATE makes the build fetch tagwright's own
# modules directly from their source rather than through the public module proxy.
# go.sum still verifies their integrity. The build context is this one repo with
# no sibling module directories, which is the clean-room that a committed local
# `replace` would fail: a stale replace pointing at ../core or ../beacon breaks
# the build here.

FROM golang:1.25 AS build

ENV GOPRIVATE=github.com/tagwright/*

# Pinned sops. The daemon drives sops for decryption and must never ship a
# distro's stale build, so pull an exact, checksum-verified release straight
# from GitHub and fail the build on a mismatch. sops has built-in age support,
# so at runtime the daemon points it at the age key via SOPS_AGE_KEY_FILE and no
# separate age binary is needed in the image. This targets linux/amd64 only (the
# server this image runs on). arm64 is a follow-up if it is ever needed.
ARG SOPS_VERSION=3.9.4
ARG SOPS_SHA256=5488e32bc471de7982ad895dd054bbab3ab91c417a118426134551e9626e4e85

RUN wget -O /tmp/sops "https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.linux.amd64" \
    && echo "${SOPS_SHA256}  /tmp/sops" | sha256sum -c - \
    && install -m 0755 /tmp/sops /usr/local/bin/sops \
    && rm /tmp/sops \
    && sops --version

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build all three binaries CGO-free so they run on distroless static, and stamp
# the version from the VERSION file into the shared version package so every
# binary's version output matches the release tag.
RUN VERSION="$(cat VERSION)" \
    && LDFLAGS="-s -w -X github.com/tagwright/berm/internal/version.Version=${VERSION}" \
    && CGO_ENABLED=0 go build -buildvcs=false -ldflags "${LDFLAGS}" -o /out/berm ./cmd/berm \
    && CGO_ENABLED=0 go build -buildvcs=false -ldflags "${LDFLAGS}" -o /out/berm-client ./cmd/berm-client \
    && CGO_ENABLED=0 go build -buildvcs=false -ldflags "${LDFLAGS}" -o /out/berm-hook ./cmd/berm-hook

# Distroless static, the ROOT variant (not :nonroot) deliberately: the daemon
# reads the container socket and walks /proc to authenticate a caller by its
# peer credential (SO_PEERCRED to PID to cgroup to container id), which needs
# uid 0 in the host PID namespace. The image ships no shell, no package manager,
# and nothing that can open a network connection on its own. The no-egress
# guarantee is a RUNTIME setting the operator sets on the daemon service (see
# deploy/, network_mode: none or an internal gateway-less network). The image
# simply carries nothing that could phone out.
FROM gcr.io/distroless/static-debian12

# The daemon binary the entrypoint runs, and the pinned decryption backend it
# drives.
COPY --from=build /out/berm /usr/local/bin/berm
COPY --from=build /usr/local/bin/sops /usr/local/bin/sops

# berm-client and berm-hook are carried here so an operator can lift them into an
# app image with a single COPY --from, no separate download or checksum:
#
#   COPY --from=ghcr.io/tagwright/berm:<tag> /usr/local/bin/berm-client /usr/local/bin/berm-client
#   COPY --from=ghcr.io/tagwright/berm:<tag> /usr/local/bin/berm-hook   /usr/local/bin/berm-hook
COPY --from=build /out/berm-client /usr/local/bin/berm-client
COPY --from=build /out/berm-hook /usr/local/bin/berm-hook

ENTRYPOINT ["berm"]
CMD ["daemon"]
