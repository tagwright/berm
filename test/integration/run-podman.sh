#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# berm integration harness (nested-Podman path, chunk 9b).
#
# This is the FIRST live exercise of the Podman runtime, the OCI pre-start HOOK
# delivery, and the container-mount-namespace write that earlier chunks unit
# tested but deferred proving here. It mirrors ballast's nested-podman pattern: a
# throwaway, self-contained rootful Podman is stood up by running
# quay.io/podman/stable (--privileged, for Podman's own nested runtime), and the
# berm daemon, the OCI hook, and the app containers all run INSIDE that Podman.
# There is no dependency on a Podman install on the host running this harness.
#
# It proves, live, against a real Podman socket and real crun-created containers:
#
#   1. HOOK mode end to end. The berm-hook OCI hook is installed via Podman's
#      hooks_dir, fires at the createContainer stage for a berm.enable-annotated
#      container, connects to the daemon over the hook-request protocol, and
#      writes the file secret into the container's OWN mount namespace, on tmpfs,
#      BEFORE PID 1, byte-exact to the known plaintext, with the numeric owner
#      and mode. The age key never reaches the app container.
#   2. Hook files-only. An env declaration under hook mode is refused end to end
#      (resolve + the hook handler refuse env), which fails that one container's
#      start loudly, while the rest of the fleet is still served.
#   3. Podman runtime for the other modes. The daemon selects the Podman runtime
#      (BERM_RUNTIME=podman), and CLIENT mode (peer-authed through the libpod
#      cgroup topology, exercising peerauth's cgroup parsing for real) and VOLUME
#      mode (the waiter/manifest ready-signal, populated off a live Podman start
#      event) both work under Podman.
#   4. Compose/pod identity. A container identified only by a compose SERVICE
#      label (no berm.name) resolves to the matching source under Podman.
#   5. Rootless observations. A best-effort rootless-Podman hook probe records
#      what does and does not hold without privilege (the architecture's flagged
#      rootless-hook item), documented honestly rather than asserted green.
#
# Every object this script creates is prefixed berm-itest- (Docker container,
# images, volumes; and every Podman object created inside the nested Podman) and
# torn down in a trap that runs on success, failure, or interrupt. There is no
# host Go toolchain requirement: all Go builds run in golang:1.25. Host sops is
# used only to ENCRYPT the throwaway fixtures; the daemon does all decryption.
#
# Run:  bash test/integration/run-podman.sh [--keep]
#   --keep   skip cleanup at the end (to debug a failure by hand)

set -uo pipefail

# --- paths and constants ---------------------------------------------------

ITEST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$ITEST/../.." && pwd)"

PODMAN_HOST=berm-itest-podman          # the podman-in-docker container
IMG=berm-itest-podimg:latest           # berm daemon image
APPIMG=berm-itest-podapp:latest        # app image (probe + berm-client on alpine)
DAEMON=berm-itest-daemon               # the daemon, a podman container inside PiD
GOCACHE_VOL=berm-itest-gocache
PODVOL=berm-itest-podvol               # tmpfs named volume for volume mode

SRC="$ITEST/sources-podman"            # generated ciphertext (gitignored)
KEYS="$ITEST/keys-podman"              # generated age key   (gitignored)
OUT="$ITEST/out-podman"                # built helper binaries (gitignored)

# Known plaintext values. The no-leak proof is that none of these appears where
# it must not (a daemon log, an app fs other than the tmpfs target).
V_FILEVAL="fileval-secret-HOOK-33333333"
V_SECRET_A="alpha-secret-CLIENT-11111111"
V_SECRET_V="victor-secret-VOLUME-55555555"
V_COMPOSE="compose-secret-IDENT-77777777"
V_ENVTOKEN="envtoken-secret-EEE-44444444"

KEEP=0
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

PASS=0
FAIL=0
declare -a FAILED_NAMES=()

pass() { PASS=$((PASS + 1)); printf 'PASS  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); FAILED_NAMES+=("$1"); printf 'FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }
info() { printf 'NOTE  %s\n' "$1"; }
assert_eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "expected [$2] got [$3]"; fi; }
assert_contains() { if printf '%s' "$2" | grep -qF -- "$3"; then pass "$1"; else fail "$1" "missing [$3]"; fi; }
assert_absent() { if printf '%s' "$2" | grep -qF -- "$3"; then fail "$1" "unexpectedly found [$3]"; else pass "$1"; fi; }
log() { printf '\n=== %s ===\n' "$1"; }

sha_of() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

# ph runs a podman command inside the nested-Podman host (rootful).
ph() { docker exec "$PODMAN_HOST" podman "$@"; }
# dlogs returns the daemon container's logs (the daemon is a podman container).
dlogs() { docker exec "$PODMAN_HOST" podman logs "$DAEMON" 2>&1; }

# --- cleanup ---------------------------------------------------------------

cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    log "SKIP CLEANUP (--keep)"
    printf 'remove by hand: docker rm -f %s ; docker rmi %s %s ; docker volume rm %s\n' \
      "$PODMAN_HOST" "$IMG" "$APPIMG" "$GOCACHE_VOL"
    return
  fi
  log "CLEANUP"
  # Everything created inside the nested Podman dies with the PiD container, so a
  # single docker rm -f reclaims the daemon, the hook, every app container, the
  # named volume, and the loaded images. Then the Docker-level objects.
  docker rm -f "$PODMAN_HOST" >/dev/null 2>&1 || true
  docker rmi -f "$APPIMG" >/dev/null 2>&1 || true
  if [ "${RM_IMG:-0}" = "1" ]; then docker rmi -f "$IMG" >/dev/null 2>&1 || true; fi
  docker volume rm -f "$GOCACHE_VOL" >/dev/null 2>&1 || true
  rm -rf "$SRC" "$KEYS" "$OUT" 2>/dev/null || true

  log "LEAK CHECK"
  local leaks
  leaks="$(docker ps -aq --filter "name=berm-itest-" 2>/dev/null)"
  leaks="$leaks$(docker volume ls -q --filter "name=berm-itest-" 2>/dev/null | grep -v "^$GOCACHE_VOL$" || true)"
  leaks="$leaks$(docker network ls -q --filter "name=berm-itest-" 2>/dev/null)"
  if [ -n "$leaks" ]; then
    printf 'LEAK: berm-itest-* objects survived cleanup:\n%s\n' "$leaks"
  else
    printf 'no berm-itest-* containers, volumes, or networks survived cleanup\n'
  fi
}
trap cleanup EXIT

# --- setup: build image, app image, helpers, fixtures ----------------------

setup_build() {
  log "SETUP: berm daemon image"
  if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    docker build -t "$IMG" "$REPO" || { echo "berm image build failed"; exit 1; }
  fi
  echo "berm image: $(docker image inspect "$IMG" --format '{{.Id}}' | cut -c8-19)"

  rm -rf "$SRC" "$KEYS" "$OUT"; mkdir -p "$SRC" "$KEYS" "$OUT"

  log "SETUP: build probe + age-keygen (golang:1.25, no host Go)"
  docker volume create "$GOCACHE_VOL" >/dev/null 2>&1 || true
  docker run --rm \
    -v "$ITEST/tools/probe":/w -w /w \
    -v "$OUT":/out -v "$GOCACHE_VOL":/go \
    -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
    "golang:1.25" go build -o /out/probe . || { echo "probe build failed"; exit 1; }
  docker run --rm \
    -v "$OUT":/out -v "$GOCACHE_VOL":/go \
    -e CGO_ENABLED=0 -e GOBIN=/out -e GOFLAGS=-buildvcs=false \
    "golang:1.25" go install filippo.io/age/cmd/age-keygen@v1.2.1 \
    || { echo "age-keygen build failed"; exit 1; }
  [ -x "$OUT/probe" ] && [ -x "$OUT/age-keygen" ] || { echo "helpers missing"; exit 1; }

  log "SETUP: extract berm-client + berm-hook from the image"
  local cid; cid="$(docker create "$IMG")"
  docker cp "$cid":/usr/local/bin/berm-client "$OUT/berm-client" || { docker rm -f "$cid" >/dev/null; echo "berm-client extract failed"; exit 1; }
  docker cp "$cid":/usr/local/bin/berm-hook "$OUT/berm-hook"     || { docker rm -f "$cid" >/dev/null; echo "berm-hook extract failed"; exit 1; }
  docker rm -f "$cid" >/dev/null

  log "SETUP: app image (berm-client + probe on alpine)"
  cat > "$OUT/Dockerfile.app" <<'EOF'
FROM alpine:3.20
COPY berm-client /usr/local/bin/berm-client
COPY probe /usr/local/bin/probe
ENTRYPOINT []
EOF
  docker build -t "$APPIMG" -f "$OUT/Dockerfile.app" "$OUT" || { echo "app image build failed"; exit 1; }

  log "SETUP: age key + encrypted fixture sources"
  "$OUT/age-keygen" -o "$KEYS/default.key" 2>"$KEYS/.keygen.err" || { cat "$KEYS/.keygen.err"; echo "age-keygen failed"; exit 1; }
  RECIP="$(grep -oE 'age1[0-9a-z]+' "$KEYS/default.key" | head -1)"
  [ -n "$RECIP" ] || { echo "no age recipient parsed"; exit 1; }
  echo "age recipient: $RECIP"

  enc_dotenv() { # name  KEY=VAL[,KEY=VAL...]
    local name="$1"; shift
    local plain="$SRC/.$name.plain"; : > "$plain"
    local kv; for kv in "$@"; do printf '%s\n' "$kv" >> "$plain"; done
    sops --config /dev/null -e --age "$RECIP" --input-type dotenv --output-type dotenv "$plain" > "$SRC/$name.sops.env" \
      || { echo "sops encrypt $name failed"; exit 1; }
    rm -f "$plain"
  }
  enc_dotenv svcenv     "FILEVAL=$V_FILEVAL" "ENVTOKEN=$V_ENVTOKEN"
  enc_dotenv svca       "SECRET_A=$V_SECRET_A"
  enc_dotenv svcv       "SECRET_V=$V_SECRET_V"
  enc_dotenv svcompose  "COMPOSE_SECRET=$V_COMPOSE"
}

# --- setup: stand up nested Podman, install hook, load images --------------

setup_podman() {
  log "SETUP: nested Podman ($PODMAN_HOST)"
  docker rm -f "$PODMAN_HOST" >/dev/null 2>&1 || true
  docker run -d --name "$PODMAN_HOST" --privileged \
    quay.io/podman/stable:latest sleep infinity >/dev/null || { echo "PiD start failed"; exit 1; }

  local i
  for i in $(seq 1 30); do docker exec "$PODMAN_HOST" podman version >/dev/null 2>&1 && break; sleep 1; done
  echo "podman: $(ph version --format '{{.Server.Version}}')  crun: $(docker exec "$PODMAN_HOST" crun --version 2>/dev/null | head -1)"

  log "SETUP: configure hooks_dir + install berm-hook + hook definition"
  # On current Podman the built-in hooks_dir default does not reliably include
  # /etc/containers/oci/hooks.d, so set it explicitly (documented in
  # deploy/hook/README.md).
  docker exec "$PODMAN_HOST" mkdir -p /etc/containers /etc/containers/oci/hooks.d /run/berm /run/podman /opt/berm
  # k8s-file log driver so `podman logs` is readable in this nested env (the
  # default journald driver has no journal to read here). This is a harness-only
  # concern, not a berm requirement.
  docker exec "$PODMAN_HOST" bash -c 'printf "[containers]\nlog_driver = \"k8s-file\"\n\n[engine]\nhooks_dir = [\"/etc/containers/oci/hooks.d\"]\n" > /etc/containers/containers.conf'
  docker cp "$OUT/berm-hook" "$PODMAN_HOST":/usr/local/bin/berm-hook
  docker exec "$PODMAN_HOST" chmod 0755 /usr/local/bin/berm-hook
  # Ship the REAL hook definition from the repo (createContainer stage).
  docker cp "$REPO/deploy/hook/hooks.d/berm-hook.json" "$PODMAN_HOST":/etc/containers/oci/hooks.d/berm-hook.json
  echo "installed hook:"; docker exec "$PODMAN_HOST" cat /etc/containers/oci/hooks.d/berm-hook.json

  log "SETUP: load berm + app images into the nested Podman"
  docker save "$IMG"    | docker exec -i "$PODMAN_HOST" podman load >/dev/null || { echo "podman load berm failed"; exit 1; }
  docker save "$APPIMG" | docker exec -i "$PODMAN_HOST" podman load >/dev/null || { echo "podman load app failed"; exit 1; }

  log "SETUP: start the Podman compat API socket (the daemon's runtime socket)"
  docker exec -d "$PODMAN_HOST" podman system service --time=0 unix:///run/podman/podman.sock
  for i in $(seq 1 30); do
    if docker exec "$PODMAN_HOST" test -S /run/podman/podman.sock 2>/dev/null; then break; fi
    sleep 1
  done
  docker exec "$PODMAN_HOST" test -S /run/podman/podman.sock || { echo "podman compat socket never appeared"; docker exec "$PODMAN_HOST" ls -la /run/podman/ 2>&1; exit 1; }
  # Confirm it actually answers.
  docker exec "$PODMAN_HOST" podman --url unix:///run/podman/podman.sock version >/dev/null 2>&1 || { echo "podman compat socket not answering"; exit 1; }
  echo "podman compat socket up"

  log "SETUP: provision fixtures + volume, then start the berm daemon (podman container, pid host)"
  docker cp "$SRC" "$PODMAN_HOST":/opt/berm/sources
  docker cp "$KEYS" "$PODMAN_HOST":/opt/berm/age
  docker cp "$ITEST/berm-podman.yml" "$PODMAN_HOST":/opt/berm/berm.yml
  # The tmpfs named volume for volume mode, mounted into BOTH the daemon (to
  # write) and the app (to read), must exist before the daemon starts.
  ph volume create --opt type=tmpfs --opt device=tmpfs "$PODVOL" >/dev/null

  ph rm -f "$DAEMON" >/dev/null 2>&1 || true
  ph run -d --name "$DAEMON" \
    --pid host \
    -v /run/podman/podman.sock:/run/podman/podman.sock:ro \
    -v /run/berm:/run/berm \
    -v /opt/berm/sources:/var/lib/berm/sources:ro \
    -v /opt/berm/age:/run/berm/age:ro \
    -v /opt/berm/berm.yml:/etc/berm/berm.yml:ro \
    -v "$PODVOL":/run/berm/volumes/svcvvol \
    -e BERM_RUNTIME=podman \
    -e BERM_SOCKET=/run/podman/podman.sock \
    -e BERM_SOURCES_ROOT=/var/lib/berm/sources \
    "$IMG" daemon --config /etc/berm/berm.yml --socket /run/berm/berm.sock >/dev/null \
    || { echo "daemon start failed"; exit 1; }

  for i in $(seq 1 40); do dlogs | grep -q "berm daemon started" && break; sleep 0.3; done
  if ! dlogs | grep -q "berm daemon started"; then
    echo "daemon never reported started; logs:"; dlogs; exit 1
  fi
  echo "daemon up (runtime=podman):"; dlogs | grep -i "berm daemon started" | head -1
}

# ==========================================================================
# PHASE 1: HOOK mode end to end (the deferred setns/mount-ns write, live)
# ==========================================================================
phase_hook_happy() {
  log "HOOK: end-to-end file injection into the container's own mount ns before PID 1"
  local NAME=berm-itest-hookapp
  ph rm -f "$NAME" >/dev/null 2>&1 || true
  # In hook mode the whole berm.* config is set as OCI ANNOTATIONS: the trusted
  # hook reads them from the OCI state it is handed and presents them to the
  # daemon, so the daemon never has to inspect the mid-creation container over the
  # runtime API (which would deadlock against the create that the hook blocks).
  # PID 1 records, as its very first act, whether the secret is already present,
  # proving the write happened BEFORE PID 1.
  ph run -d --name "$NAME" \
    --tmpfs /run/berm \
    --annotation berm.enable=true \
    --annotation berm.name=svcenv \
    --annotation berm.delivery=hook \
    --annotation berm.file.tok.from=FILEVAL \
    --annotation berm.file.tok.owner=1000 \
    --annotation berm.file.tok.mode=0440 \
    "$APPIMG" sh -c 'if [ -e /run/berm/tok ]; then echo BERM_BOOT_SAW_TOK; else echo BERM_BOOT_NO_TOK; fi; exec probe hold' \
    >/dev/null 2>"$OUT/hookrun.err"
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "hook happy: container started" "podman run rc=$rc: $(cat "$OUT/hookrun.err")"
    return
  fi
  sleep 1
  local st; st="$(ph inspect "$NAME" --format '{{.State.Status}}' 2>/dev/null)"
  if [ "$st" != "running" ]; then
    fail "hook happy: container reached running" "status=$st logs: $(ph logs "$NAME" 2>&1 | tail -5)"
    return
  fi
  pass "hook happy: berm-enabled container started with the OCI hook installed"

  # 1. Written BEFORE PID 1.
  local boot; boot="$(ph logs "$NAME" 2>&1)"
  assert_contains "hook happy: secret present at PID 1's first instruction (written before PID 1)" "$boot" "BERM_BOOT_SAW_TOK"

  # 2. Byte-exact on tmpfs with numeric owner + mode.
  assert_eq "hook happy: file secret byte-exact on the container tmpfs" "$(sha_of "$V_FILEVAL")" "$(ph exec "$NAME" probe sha256 /run/berm/tok 2>/dev/null)"
  assert_eq "hook happy: delivered owner uid + mode (want '1000 0 0440')" "1000 0 0440" "$(ph exec "$NAME" probe stat /run/berm/tok 2>/dev/null)"
  assert_eq "hook happy: delivery dir is tmpfs (own mount ns), not persistent disk" "tmpfs" "$(ph exec "$NAME" probe statfs /run/berm 2>/dev/null)"

  # 3. Manifest landed too.
  ph exec "$NAME" probe has /run/berm/manifest 2>/dev/null && pass "hook happy: manifest written on the container tmpfs" || fail "hook happy: manifest present"

  # 4. The daemon validated the presented id (trusted-injector path), no leak.
  assert_absent "hook happy: no secret value in the daemon log" "$(dlogs)" "$V_FILEVAL"

  # 5. The age key never reaches the app container.
  local ak; ak="$(ph export "$NAME" 2>/dev/null | grep -a -c 'AGE-SECRET-KEY' || true)"
  assert_eq "hook happy: age secret key absent from the app container fs" "0" "$ak"
  # And the plaintext exists ONLY on the tmpfs, nowhere else in the app rootfs
  # (docker/podman export streams the container fs, excluding the tmpfs mount).
  local fx; fx="$(ph export "$NAME" 2>/dev/null | grep -a -c -- "$V_FILEVAL" || true)"
  assert_eq "hook happy: secret plaintext absent from the app's persistent rootfs (tmpfs-only)" "0" "$fx"
}

# ==========================================================================
# PHASE 2: HOOK files-only -- env under hook mode is refused end to end
# ==========================================================================
phase_hook_env_refused() {
  log "HOOK: env declaration under hook mode is refused (files only)"
  local NAME=berm-itest-hookenv
  ph rm -f "$NAME" >/dev/null 2>&1 || true
  # A hook-mode container that also declares an env secret. The resolver refuses
  # env on the hook mechanism, the hook fetch fails, and the createContainer hook
  # returning nonzero fails this container's start -- loud refusal, no silent
  # empty delivery.
  ph run -d --name "$NAME" \
    --tmpfs /run/berm \
    --annotation berm.enable=true \
    --annotation berm.name=svcenv \
    --annotation berm.delivery=hook \
    --annotation berm.env=ENVTOKEN \
    --annotation berm.env.acknowledge=true \
    "$APPIMG" probe hold >/dev/null 2>"$OUT/hookenv.err"
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    pass "hook env: container start REFUSED (hook returned nonzero, no silent empty delivery)"
  else
    local st; st="$(ph inspect "$NAME" --format '{{.State.Status}}' 2>/dev/null)"
    if [ "$st" = "running" ]; then
      fail "hook env: env under hook mode must be refused" "container is running (rc=$rc, status=$st)"
    else
      pass "hook env: container did not run (start refused, status=$st)"
    fi
  fi
  sleep 1
  assert_contains "hook env: daemon classified env_wrong_mechanism" "$(dlogs)" "env_wrong_mechanism"
  assert_absent "hook env: no env secret value in the daemon log" "$(dlogs)" "$V_ENVTOKEN"

  # The fleet still serves: a fresh hook-mode container without env still works.
  local OK=berm-itest-hookafter
  ph rm -f "$OK" >/dev/null 2>&1 || true
  ph run -d --name "$OK" --tmpfs /run/berm \
    --annotation berm.enable=true --annotation berm.name=svcenv --annotation berm.delivery=hook \
    --annotation berm.file.tok.from=FILEVAL \
    "$APPIMG" probe hold >/dev/null 2>&1
  sleep 1
  if [ "$(ph inspect "$OK" --format '{{.State.Status}}' 2>/dev/null)" = "running" ]; then
    assert_eq "hook env: fleet still served (a fresh files-only hook container works)" "$(sha_of "$V_FILEVAL")" "$(ph exec "$OK" probe sha256 /run/berm/tok 2>/dev/null)"
  else
    fail "hook env: fleet still served" "the follow-up hook container did not run"
  fi
}

# ==========================================================================
# PHASE 3: CLIENT mode under Podman (peer-auth via the libpod cgroup topology)
# ==========================================================================
phase_client() {
  log "CLIENT: peer-authed fetch under Podman (SO_PEERCRED -> libpod cgroup -> id)"
  local NAME=berm-itest-client
  ph rm -f "$NAME" >/dev/null 2>&1 || true
  # Mount the daemon's listen socket in; the client fetches and execs the app.
  ph run -d --name "$NAME" \
    -v /run/berm/berm.sock:/run/berm-sock/berm.sock \
    --tmpfs /run/berm \
    -e BERM_SOCK=/run/berm-sock/berm.sock \
    --label berm.enable=true --label berm.name=svca --label berm.delivery=client \
    --label berm.file.a.from=SECRET_A \
    "$APPIMG" berm-client exec -- probe hold >/dev/null 2>"$OUT/clientrun.err"
  sleep 2
  local st; st="$(ph inspect "$NAME" --format '{{.State.Status}}' 2>/dev/null)"
  if [ "$st" != "running" ]; then
    fail "client: container reached running" "status=$st logs: $(ph logs "$NAME" 2>&1 | tail -5); daemon: $(dlogs | tail -5)"
    return
  fi
  pass "client: berm-client fetched-and-exec'd under Podman"
  assert_eq "client: file secret byte-exact on tmpfs (peer-auth resolved the caller)" "$(sha_of "$V_SECRET_A")" "$(ph exec "$NAME" probe sha256 /run/berm/a 2>/dev/null)"
  assert_eq "client: delivered secret on tmpfs" "tmpfs" "$(ph exec "$NAME" probe statfs /run/berm 2>/dev/null)"

  # Document the libpod cgroup shape the daemon parsed (evidence for peerauth).
  local cpid; cpid="$(ph inspect "$NAME" --format '{{.State.Pid}}' 2>/dev/null)"
  local cg; cg="$(docker exec "$PODMAN_HOST" cat "/proc/$cpid/cgroup" 2>/dev/null | tr '\n' ' ')"
  info "client cgroup (PID $cpid, host pid ns): $cg"
}

# ==========================================================================
# PHASE 4: VOLUME mode under Podman (start-event push, manifest ready-signal)
# ==========================================================================
phase_volume() {
  log "VOLUME: tmpfs named volume, populated off a live Podman start event"
  local NAME=berm-itest-volapp
  ph rm -f "$NAME" >/dev/null 2>&1 || true
  ph run -d --name "$NAME" \
    -v "$PODVOL":/run/berm \
    --label berm.enable=true --label berm.name=svcv --label berm.delivery=volume \
    --label berm.volume=svcvvol --label berm.file.v.from=SECRET_V \
    "$APPIMG" probe hold >/dev/null 2>"$OUT/volrun.err"
  sleep 1
  if [ "$(ph inspect "$NAME" --format '{{.State.Status}}' 2>/dev/null)" != "running" ]; then
    fail "volume: app container running" "$(ph logs "$NAME" 2>&1 | tail -3)"
    return
  fi
  # Wait for the daemon to react to the start event and write the manifest.
  local i ok=0
  for i in $(seq 1 30); do
    if ph exec "$NAME" probe has /run/berm/manifest 2>/dev/null; then ok=1; break; fi
    sleep 0.5
  done
  if [ "$ok" -eq 1 ]; then
    pass "volume: daemon populated the shared tmpfs volume (manifest ready-signal appeared)"
  else
    fail "volume: manifest never appeared" "daemon: $(dlogs | tail -6)"
    return
  fi
  assert_eq "volume: app reads its file secret byte-exact from the tmpfs volume" "$(sha_of "$V_SECRET_V")" "$(ph exec "$NAME" probe sha256 /run/berm/v 2>/dev/null)"
  assert_eq "volume: delivered secret on tmpfs" "tmpfs" "$(ph exec "$NAME" probe statfs /run/berm 2>/dev/null)"
}

# ==========================================================================
# PHASE 5: Compose/pod service-identity derivation under Podman
# ==========================================================================
phase_compose_identity() {
  log "IDENTITY: compose SERVICE label (no berm.name) resolves to the matching source"
  local NAME=berm-itest-composed
  ph rm -f "$NAME" >/dev/null 2>&1 || true
  # No berm.name: the service identity must come from the compose service
  # annotation the hook presents (berm's hook-mode identity derivation). The
  # matching berm.yml source is svcompose.
  ph run -d --name "$NAME" \
    --tmpfs /run/berm \
    --annotation berm.enable=true \
    --annotation berm.delivery=hook \
    --annotation com.docker.compose.project=berm-itest \
    --annotation com.docker.compose.service=svcompose \
    --annotation berm.file.c.from=COMPOSE_SECRET \
    "$APPIMG" probe hold >/dev/null 2>"$OUT/idrun.err"
  local rc=$?
  sleep 1
  local st; st="$(ph inspect "$NAME" --format '{{.State.Status}}' 2>/dev/null)"
  if [ "$rc" -ne 0 ] || [ "$st" != "running" ]; then
    fail "identity: compose-identified hook container started" "rc=$rc status=$st err=$(cat "$OUT/idrun.err"); daemon: $(dlogs | tail -5)"
    return
  fi
  assert_eq "identity: resolved svcompose source from the compose service label alone" "$(sha_of "$V_COMPOSE")" "$(ph exec "$NAME" probe sha256 /run/berm/c 2>/dev/null)"
}

# ==========================================================================
# PHASE 6: Rootless-Podman hook probe (best-effort, documented honestly)
# ==========================================================================
phase_rootless() {
  log "ROOTLESS: best-effort rootless-Podman hook probe (architecture's flagged item)"
  # The quay.io/podman/stable image ships a preconfigured rootless 'podman' user.
  # We probe, as that user, whether the createContainer hook fires and whether the
  # mount-ns write works without privilege. This is the rootless-hook friction the
  # architecture asked to prototype; we record what we observe, not a green.
  local RL="docker exec -u podman -e XDG_RUNTIME_DIR=/run/user/1000 -e HOME=/home/podman $PODMAN_HOST"
  docker exec "$PODMAN_HOST" bash -c 'id podman >/dev/null 2>&1 && loginctl enable-linger podman 2>/dev/null; mkdir -p /run/user/1000 && chown podman:podman /run/user/1000' 2>/dev/null || true
  # Rootless reads hooks from the user config dir; mirror the rootful hook there.
  docker exec "$PODMAN_HOST" bash -c 'mkdir -p /home/podman/.config/containers/oci/hooks.d /home/podman/.config/containers && cp /etc/containers/oci/hooks.d/berm-hook.json /home/podman/.config/containers/oci/hooks.d/ && printf "[engine]\nhooks_dir = [\"/home/podman/.config/containers/oci/hooks.d\"]\n" > /home/podman/.config/containers/containers.conf && chown -R podman:podman /home/podman/.config' 2>/dev/null || true

  if ! $RL podman info >/dev/null 2>&1; then
    info "rootless podman could not initialize in this nested environment; ROOTLESS HOOK PATH UNPROVEN here"
    info "reason: rootless podman needs a working user session/subuid mapping the privileged PiD does not fully provide"
    return
  fi
  $RL podman rm -f berm-itest-rootless >/dev/null 2>&1 || true
  # A minimal rootless hook probe: does the createContainer hook even fire and can
  # it write into the container? The daemon socket is root-owned at /run/berm, so a
  # full rootless end-to-end is not wired here; we observe hook firing + write.
  local out
  out="$($RL podman run --rm --tmpfs /run/berm \
      --annotation berm.enable=true --annotation berm.name=svcenv --annotation berm.delivery=hook \
      --annotation berm.file.tok.from=FILEVAL \
      "$APPIMG" sh -c 'ls -la /run/berm 2>&1; test -e /run/berm/tok && echo ROOTLESS_TOK_PRESENT || echo ROOTLESS_TOK_ABSENT' 2>&1)"
  info "rootless probe output: $(printf '%s' "$out" | tr '\n' '|')"
  if printf '%s' "$out" | grep -q ROOTLESS_TOK_PRESENT; then
    info "ROOTLESS: the hook fired and wrote into the container tmpfs even rootless (mount-ns write not root-gated)"
  else
    info "ROOTLESS: hook did not deliver rootless here (expected friction: root-owned daemon socket and/or userns uid mapping). Documented, not asserted."
  fi
}

# --- main ------------------------------------------------------------------

main() {
  setup_build
  setup_podman
  phase_hook_happy
  phase_hook_env_refused
  phase_client
  phase_volume
  phase_compose_identity
  phase_rootless

  log "RESULT"
  printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
  if [ "$FAIL" -ne 0 ]; then
    printf 'failed assertions:\n'; printf '  - %s\n' "${FAILED_NAMES[@]}"
    return 1
  fi
  printf 'all nested-podman integration assertions passed\n'
  return 0
}

main
RC=$?
exit "$RC"
