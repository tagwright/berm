#!/usr/bin/env bash
# Live gate-2 harness runner (see docs/EMPIRICAL.md, gate 2).
#
# Proves that SO_PEERCRED on a berm daemon socket resolves the peer pid back to
# the CLIENT container through the socket-bind-mount topology, and finds the
# minimal deployment condition. Stands up sibling daemon/client containers, all
# prefixed berm-itest-, and cleans every one up on exit even on failure. It
# operates only on objects it creates and never touches any running stack.
#
# Run this on a host with a live Docker socket. It builds a static harness
# binary in a golang:1.25 container, so no host Go toolchain is needed.
#
# The shared directory must be a HOST path (bind mounts into the sibling
# containers resolve on the host). This script uses a mktemp dir, which is
# correct when run directly on the host. If you run it from inside a container,
# set SHARED to a path that is identical on the host and in that container.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHARED="${SHARED:-$(mktemp -d)}"
DAEMON="berm-itest-gate2-daemon"
CLIENT="berm-itest-gate2-client"
SOCK="/shared/berm.sock"
IMG="alpine:3.20"

cleanup() {
  echo "=== CLEANUP ==="
  docker rm -f "$DAEMON" "$CLIENT" >/dev/null 2>&1 || true
  rm -rf "$SHARED" 2>/dev/null || true
  echo "cleaned containers and $SHARED"
}
trap cleanup EXIT

mkdir -p "$SHARED"
chmod 777 "$SHARED"

echo "=== BUILD static gate2 binary ==="
docker run --rm \
  -v "$REPO_DIR":/work -w /work \
  -v "$SHARED":/out \
  -e GOPRIVATE='github.com/tagwright/*' -e GOFLAGS=-buildvcs=false \
  -e CGO_ENABLED=0 \
  golang:1.25 sh -c "go build -o /out/gate2 ./test/peerauth/gate2 && ls -l /out/gate2" || exit 1

docker pull -q "$IMG" >/dev/null 2>&1 || true

run_scenario() {
  local label="$1"; shift
  local daemon_extra=("$@")
  echo
  echo "############################################################"
  echo "# SCENARIO: $label"
  echo "#   daemon extra flags: ${daemon_extra[*]:-(none)}"
  echo "############################################################"

  docker rm -f "$DAEMON" "$CLIENT" >/dev/null 2>&1 || true
  rm -f "$SHARED/berm.sock"

  docker run -d --name "$DAEMON" \
    "${daemon_extra[@]}" \
    -v "$SHARED":/shared \
    -v /var/run/docker.sock:/var/run/docker.sock \
    "$IMG" /shared/gate2 daemon "$SOCK" >/dev/null || { echo "daemon start failed"; return; }

  for _ in $(seq 1 50); do
    [ -S "$SHARED/berm.sock" ] && break
    sleep 0.2
  done
  if [ ! -S "$SHARED/berm.sock" ]; then
    echo "socket never appeared; daemon logs:"; docker logs "$DAEMON" 2>&1; return
  fi

  docker run -d --name "$CLIENT" \
    -v "$SHARED":/shared \
    "$IMG" /shared/gate2 client "$SOCK" >/dev/null || { echo "client start failed"; return; }
  local client_id
  client_id=$(docker inspect -f '{{.Id}}' "$CLIENT")
  echo ">>> CLIENT real container id: $client_id"

  docker wait "$CLIENT" >/dev/null 2>&1 || true
  sleep 1

  echo "--- DAEMON LOG ---"
  docker logs "$DAEMON" 2>&1
  echo "--- END DAEMON LOG ---"

  local resolved
  resolved=$(docker logs "$DAEMON" 2>&1 | grep -o '"container_id":"[0-9a-f]*"' | head -1 | cut -d'"' -f4)
  if [ -n "$resolved" ] && [ "$resolved" = "$client_id" ]; then
    echo ">>> VERDICT [$label]: RESOLVED CORRECTLY (daemon id == client id)"
  elif [ -n "$resolved" ]; then
    echo ">>> VERDICT [$label]: RESOLVED WRONG CONTAINER ($resolved != $client_id)"
  else
    echo ">>> VERDICT [$label]: DID NOT RESOLVE (fail-closed)"
  fi

  docker rm -f "$DAEMON" "$CLIENT" >/dev/null 2>&1 || true
}

run_scenario "A: no pid:host, default cgroupns"
run_scenario "B: --pid=host, default cgroupns" --pid=host
run_scenario "C: --pid=host + --cgroupns=host" --pid=host --cgroupns=host

echo
echo "=== ALL SCENARIOS DONE ==="
