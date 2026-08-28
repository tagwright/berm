#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# berm integration harness (Docker path, chunk 9a).
#
# Drives the REAL berm daemon image against LIVE Docker containers over the real
# Docker socket, and proves the end-to-end paths, the security spine, and the
# failure paths of berm's secrets injection. Every object it creates is prefixed
# berm-itest- and torn down in a trap that runs even on failure. It operates only
# on objects it creates, uses network_mode none plus a private socket volume so
# it never touches any running stack, and never docker-composes the stack.
#
# Requirements: a live Docker socket, host `sops` (used only to ENCRYPT the
# throwaway fixture sources; the daemon does all decryption itself), and network
# egress once to build a static age-keygen and pull base images. There is no host
# Go toolchain: all Go builds run in a golang:1.25 container.
#
# The berm daemon image must be built first (the harness builds it if absent):
#   docker build -t berm-itest-img:latest <repo-root>
#
# Run:  bash test/integration/run.sh
# It prints a PASS/FAIL line per assertion and a final tally, exiting nonzero if
# any assertion failed or any berm-itest-* object leaked.

set -uo pipefail

# --- paths and constants ---------------------------------------------------

ITEST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$ITEST/../.." && pwd)"
IMG="berm-itest-img:latest"
APPIMG="berm-itest-app:latest"
DAEMON="berm-itest-daemon"
SOCK_VOL="berm-itest-sock"
STATE_VOL="berm-itest-state"
TMPFS_VOL="berm-itest-vol"
GOCACHE_VOL="berm-itest-gocache"
SOCK_IN_APP="/run/berm-sock/berm.sock"

SRC="$ITEST/sources"   # generated ciphertext (gitignored)
KEYS="$ITEST/keys"     # generated age key   (gitignored)
OUT="$ITEST/out"       # built helper binaries (gitignored)

# Known plaintext values. The whole point of the no-leak proof is that NONE of
# these ever appears in a daemon log, the ledger, or the daemon's writable layer.
V_SECRET_A="alpha-secret-AAA-11111111"
V_SECRET_B="bravo-secret-BBB-22222222"
V_FILEVAL="fileval-secret-FFF-33333333"
V_ENVTOKEN="envtoken-secret-EEE-44444444"
V_SECRET_V="victor-secret-VVV-55555555"
V_DBPASS="shareddb-secret-DDD-66666666"
V_STALE_OLD="stale-secret-OLD-88888888"
V_STALE_NEW="stale-secret-NEW-99999999"
BLOB_FILE="$SRC/.blob.plain"   # binary payload plaintext (generated)

PASS=0
FAIL=0
declare -a FAILED_NAMES=()

# --- assertion helpers -----------------------------------------------------

pass() { PASS=$((PASS + 1)); printf 'PASS  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); FAILED_NAMES+=("$1"); printf 'FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }

assert_eq() { # desc expected actual
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "expected [$2] got [$3]"; fi
}
assert_contains() { # desc haystack needle
  if printf '%s' "$2" | grep -qF -- "$3"; then pass "$1"; else fail "$1" "missing [$3]"; fi
}
assert_absent() { # desc haystack needle
  if printf '%s' "$2" | grep -qF -- "$3"; then fail "$1" "unexpectedly found [$3]"; else pass "$1"; fi
}
assert_rc() { # desc expected-rc actual-rc
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "expected rc $2 got $3"; fi
}

log() { printf '\n=== %s ===\n' "$1"; }

# --- cleanup ---------------------------------------------------------------

cleanup() {
  log "CLEANUP"
  # Remove every berm-itest-* container, then the volumes, the app image, and
  # the generated state dirs. The base image berm-itest-img is left in place so a
  # rerun is fast; remove-images below drops it only when RM_IMG=1.
  local c
  for c in $(docker ps -aq --filter "name=berm-itest-" 2>/dev/null); do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  docker volume rm -f "$SOCK_VOL" "$STATE_VOL" "$TMPFS_VOL" "$GOCACHE_VOL" >/dev/null 2>&1 || true
  docker rmi -f "$APPIMG" >/dev/null 2>&1 || true
  if [ "${RM_IMG:-0}" = "1" ]; then docker rmi -f "$IMG" >/dev/null 2>&1 || true; fi
  rm -rf "$SRC" "$KEYS" "$OUT" 2>/dev/null || true

  log "LEAK CHECK"
  local leaks
  leaks="$(docker ps -aq --filter "name=berm-itest-" 2>/dev/null)"
  leaks="$leaks$(docker volume ls -q --filter "name=berm-itest-" 2>/dev/null)"
  leaks="$leaks$(docker network ls -q --filter "name=berm-itest-" 2>/dev/null)"
  if [ -n "$leaks" ]; then
    printf 'LEAK: berm-itest-* objects survived cleanup:\n%s\n' "$leaks"
  else
    printf 'no berm-itest-* containers, volumes, or networks survived cleanup\n'
  fi
}
trap cleanup EXIT

# dexec runs a command in an app container, returns its output.
dexec() { docker exec "$1" "${@:2}"; }

# dlogs returns the daemon's full logs.
dlogs() { docker logs "$DAEMON" 2>&1; }

# --- setup -----------------------------------------------------------------

setup() {
  log "SETUP: image"
  if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    docker build -t "$IMG" "$REPO" || { echo "image build failed"; exit 1; }
  fi
  echo "berm image: $(docker image inspect "$IMG" --format '{{.Id}}' | cut -c8-19)"

  rm -rf "$SRC" "$KEYS" "$OUT"; mkdir -p "$SRC" "$KEYS" "$OUT"

  log "SETUP: build probe + age-keygen (golang:1.25, no host Go)"
  docker volume create "$GOCACHE_VOL" >/dev/null
  # probe: stdlib-only, static, offline.
  docker run --rm \
    -v "$ITEST/tools/probe":/w -w /w \
    -v "$OUT":/out -v "$GOCACHE_VOL":/go \
    -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
    "golang:1.25" go build -o /out/probe . || { echo "probe build failed"; exit 1; }
  # age-keygen: to generate a real age identity for the fixtures.
  docker run --rm \
    -v "$OUT":/out -v "$GOCACHE_VOL":/go \
    -e CGO_ENABLED=0 -e GOBIN=/out -e GOFLAGS=-buildvcs=false \
    "golang:1.25" go install filippo.io/age/cmd/age-keygen@v1.2.1 \
    || { echo "age-keygen build failed"; exit 1; }
  [ -x "$OUT/probe" ] && [ -x "$OUT/age-keygen" ] || { echo "helpers missing"; exit 1; }

  log "SETUP: extract berm-client from the image"
  local cid
  cid="$(docker create "$IMG")"
  docker cp "$cid":/usr/local/bin/berm-client "$OUT/berm-client" || { docker rm -f "$cid" >/dev/null; echo "berm-client extract failed"; exit 1; }
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
  "$OUT/age-keygen" -o "$KEYS/default.key" 2>"$KEYS/.keygen.err" || { cat "$KEYS/.keygen.err"; echo "age-keygen run failed"; exit 1; }
  RECIP="$(grep -oE 'age1[0-9a-z]+' "$KEYS/default.key" | head -1)"
  [ -n "$RECIP" ] || { echo "no age recipient parsed"; exit 1; }
  echo "age recipient: $RECIP"

  enc_dotenv() { # name  KEY=VAL[,KEY=VAL...]
    local name="$1"; shift
    local plain="$SRC/.$name.plain"
    : > "$plain"
    local kv
    for kv in "$@"; do printf '%s\n' "$kv" >> "$plain"; done
    sops --config /dev/null -e --age "$RECIP" --input-type dotenv --output-type dotenv "$plain" > "$SRC/$name.sops.env" \
      || { echo "sops encrypt $name failed"; exit 1; }
    rm -f "$plain"
  }
  enc_dotenv svca     "SECRET_A=$V_SECRET_A"
  enc_dotenv svcb     "SECRET_B=$V_SECRET_B"
  enc_dotenv svcenv   "FILEVAL=$V_FILEVAL" "ENVTOKEN=$V_ENVTOKEN"
  enc_dotenv svcv     "SECRET_V=$V_SECRET_V"
  enc_dotenv shared-db "DB_PASSWORD=$V_DBPASS"
  enc_dotenv svcstale "ROTKEY=$V_STALE_OLD"

  # Binary source: a fixed payload with a newline and a NUL to prove byte-exact
  # whole-payload delivery of arbitrary bytes.
  printf 'binblob-secret-BLOB-7777\nsecond-line\x00trailing' > "$BLOB_FILE"
  sops --config /dev/null -e --age "$RECIP" --input-type binary --output-type binary "$BLOB_FILE" > "$SRC/binblob.sops.bin" \
    || { echo "sops encrypt binblob failed"; exit 1; }

  log "SETUP: volumes + daemon"
  docker volume create "$SOCK_VOL" >/dev/null
  docker volume create "$STATE_VOL" >/dev/null
  docker volume create --driver local --opt type=tmpfs --opt device=tmpfs "$TMPFS_VOL" >/dev/null

  docker run -d --name "$DAEMON" \
    --pid host \
    --network none \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -v "$ITEST/berm.yml":/etc/berm/berm.yml:ro \
    -v "$SRC":/var/lib/berm/sources:ro \
    -v "$KEYS":/run/berm/age:ro \
    -v "$SOCK_VOL":/run/berm-sock \
    -v "$STATE_VOL":/var/lib/berm \
    -v "$TMPFS_VOL":/run/berm/volumes/svcvvol \
    -e BERM_SOURCES_ROOT=/var/lib/berm/sources \
    -e BERM_DEFAULT_DELIVERY=client \
    -e BERM_CLIENT_TIMEOUT=6s \
    -e BERM_STALE_DIGEST=true \
    -e BERM_DIGEST_SCHEDULE=3s \
    "$IMG" daemon --config /etc/berm/berm.yml --socket "$SOCK_IN_APP" \
    >/dev/null || { echo "daemon start failed"; exit 1; }

  # Wait for the socket to bind (the daemon logs "berm daemon started").
  local i
  for i in $(seq 1 50); do
    dlogs | grep -q "berm daemon started" && break
    sleep 0.2
  done
  if ! dlogs | grep -q "berm daemon started"; then
    echo "daemon never reported started; logs:"; dlogs; exit 1
  fi
  echo "daemon up"
}

# run_client_app starts a client-mode app that fetches-and-execs `probe hold`,
# then waits for it to be running (or exited). It sets the berm.name and any
# extra labels/env passed. Usage:
#   run_client_app NAME [--label k=v ...] [--env K=V ...] [-- entrypoint args...]
run_app() { # NAME  (labels via LBL array, env via ENVV array, tmpfs, cmd via CMD array)
  local name="$1"; shift
  local -a args=(-d --name "$name" --network none
    -v "$SOCK_VOL":/run/berm-sock
    -e "BERM_SOCK=$SOCK_IN_APP")
  local l; for l in "${LBL[@]}"; do args+=(--label "$l"); done
  local e; for e in "${ENVV[@]:-}"; do [ -n "$e" ] && args+=(-e "$e"); done
  local t; for t in "${TMPFS[@]:-}"; do [ -n "$t" ] && args+=(--tmpfs "$t"); done
  local v; for v in "${VOLS[@]:-}"; do [ -n "$v" ] && args+=(-v "$v"); done
  docker run "${args[@]}" "$APPIMG" "${CMD[@]}"
}

reset_arrays() { LBL=(); ENVV=(); TMPFS=(); VOLS=(); CMD=(); }

# sha of a known plaintext value (no trailing newline), matching what berm
# delivers for a dotenv key value.
sha_of() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

# wait_running returns 0 once NAME is Running, 1 if it exited first, within T sec.
wait_running() { local n=$1 t=${2:-12} i; for i in $(seq 1 $((t * 5))); do
  case "$(docker inspect -f '{{.State.Status}}' "$n" 2>/dev/null)" in
    running) return 0 ;; exited) return 1 ;;
  esac; sleep 0.2; done; return 1; }

# wait_exited echoes NAME's exit code once it has exited within T sec, else -1.
wait_exited() { local n=$1 t=${2:-20} i; for i in $(seq 1 $((t * 5))); do
  if [ "$(docker inspect -f '{{.State.Status}}' "$n" 2>/dev/null)" = "exited" ]; then
    docker inspect -f '{{.State.ExitCode}}' "$n"; return 0; fi
  sleep 0.2; done; echo "-1"; return 1; }

# ==========================================================================
# HAPPY PATH: client mode end to end (file + pointer + env), the Docker primary
# ==========================================================================
phase_client_happy() {
  log "HAPPY: client mode (svcenv): file on tmpfs, _FILE pointer, env in environ not inspect"
  reset_arrays
  LBL=(berm.enable=true berm.name=svcenv berm.delivery=client
    berm.file.tok.from=FILEVAL berm.file.tok.owner=1000 berm.file.tok.mode=0440
    berm.env=ENVTOKEN berm.env.acknowledge=true)
  TMPFS=(/run/berm)
  CMD=(berm-client exec -- probe hold)
  run_app berm-itest-svcenv >/dev/null
  if ! wait_running berm-itest-svcenv 12; then
    fail "client happy: container reached running" "logs: $(docker logs berm-itest-svcenv 2>&1 | tail -3)"
    return
  fi
  pass "client happy: berm-client fetched and exec'd the app"

  local got want
  got="$(dexec berm-itest-svcenv probe sha256 /run/berm/tok 2>/dev/null)"
  want="$(sha_of "$V_FILEVAL")"
  assert_eq "client happy: file secret byte-exact on tmpfs" "$want" "$got"

  local st; st="$(dexec berm-itest-svcenv probe stat /run/berm/tok 2>/dev/null)"
  assert_eq "client happy: delivered file owner uid + mode (want '1000 0 0440')" "1000 0 0440" "$st"

  local fs; fs="$(dexec berm-itest-svcenv probe statfs /run/berm 2>/dev/null)"
  assert_eq "client happy: delivery dir is tmpfs" "tmpfs" "$fs"

  local ptr; ptr="$(dexec berm-itest-svcenv probe environ FILEVAL_FILE 2>/dev/null)"
  assert_eq "client happy: _FILE pointer env set to the tmpfs path (non-secret)" "FILEVAL_FILE=/run/berm/tok" "$ptr"

  local env1; env1="$(dexec berm-itest-svcenv probe environ ENVTOKEN 2>/dev/null)"
  assert_eq "client happy: env-delivered secret present in the app's /proc/1/environ" "ENVTOKEN=$V_ENVTOKEN" "$env1"

  local insp; insp="$(docker inspect berm-itest-svcenv --format '{{json .Config.Env}}' 2>/dev/null)"
  assert_absent "client happy: env-delivered secret ABSENT from docker inspect" "$insp" "$V_ENVTOKEN"

  # The file secret value must not appear in inspect either (it never should).
  local inspall; inspall="$(docker inspect berm-itest-svcenv 2>/dev/null)"
  assert_absent "client happy: file secret ABSENT from docker inspect" "$inspall" "$V_FILEVAL"
}

# ==========================================================================
# HAPPY PATH: binary whole-payload client delivery, byte-exact
# ==========================================================================
phase_binary() {
  log "HAPPY: binary whole-payload delivery (binblob)"
  reset_arrays
  LBL=(berm.enable=true berm.name=binblob berm.delivery=client berm.file.blob.from=binblob)
  TMPFS=(/run/berm)
  CMD=(berm-client exec -- probe hold)
  run_app berm-itest-binblob >/dev/null
  if ! wait_running berm-itest-binblob 12; then
    fail "binary: container reached running" "logs: $(docker logs berm-itest-binblob 2>&1 | tail -3)"
    return
  fi
  local got want
  got="$(dexec berm-itest-binblob probe sha256 /run/berm/blob 2>/dev/null)"
  want="$(sha256sum "$BLOB_FILE" | cut -d' ' -f1)"
  assert_eq "binary: whole binary payload byte-exact on tmpfs" "$want" "$got"
}

# ==========================================================================
# SECURITY SPINE: adversarial peer-auth isolation (A gets only sA, B only sB)
# ==========================================================================
phase_isolation() {
  log "SECURITY: adversarial peer-auth isolation (svca vs svcb)"
  reset_arrays; LBL=(berm.enable=true berm.name=svca berm.delivery=client berm.file.a.from=SECRET_A)
  TMPFS=(/run/berm); CMD=(berm-client exec -- probe hold)
  run_app berm-itest-svca >/dev/null
  reset_arrays; LBL=(berm.enable=true berm.name=svcb berm.delivery=client berm.file.b.from=SECRET_B)
  TMPFS=(/run/berm); CMD=(berm-client exec -- probe hold)
  run_app berm-itest-svcb >/dev/null

  wait_running berm-itest-svca 12 || fail "isolation: svca running" "$(docker logs berm-itest-svca 2>&1 | tail -2)"
  wait_running berm-itest-svcb 12 || fail "isolation: svcb running" "$(docker logs berm-itest-svcb 2>&1 | tail -2)"

  assert_eq "isolation: svca received its own secret A" "$(sha_of "$V_SECRET_A")" "$(dexec berm-itest-svca probe sha256 /run/berm/a 2>/dev/null)"
  assert_eq "isolation: svcb received its own secret B" "$(sha_of "$V_SECRET_B")" "$(dexec berm-itest-svcb probe sha256 /run/berm/b 2>/dev/null)"

  # A never receives B's secret and vice versa: the undeclared file is absent,
  # and B's plaintext never appears anywhere in A's filesystem export.
  dexec berm-itest-svca probe has /run/berm/b 2>/dev/null && fail "isolation: svca has NO svcb file" || pass "isolation: svca has NO svcb file"
  dexec berm-itest-svcb probe has /run/berm/a 2>/dev/null && fail "isolation: svcb has NO svca file" || pass "isolation: svcb has NO svca file"
  local expA; expA="$(docker export berm-itest-svca 2>/dev/null | grep -a -c -- "$V_SECRET_B" || true)"
  assert_eq "isolation: svcb secret never present in svca container fs" "0" "$expA"
}

# ==========================================================================
# SECURITY SPINE: cross-service grant (allowed) vs ungranted (refused, sticky)
# ==========================================================================
phase_grants() {
  log "SECURITY: positive cross-service grant (webapp reads shared-db)"
  reset_arrays; LBL=(berm.enable=true berm.name=webapp berm.delivery=client "berm.file.d.from=shared-db/DB_PASSWORD")
  TMPFS=(/run/berm); CMD=(berm-client exec -- probe hold)
  run_app berm-itest-webapp >/dev/null
  if wait_running berm-itest-webapp 12; then
    assert_eq "grant: webapp read the granted shared-db secret" "$(sha_of "$V_DBPASS")" "$(dexec berm-itest-webapp probe sha256 /run/berm/d 2>/dev/null)"
  else
    fail "grant: webapp running" "$(docker logs berm-itest-webapp 2>&1 | tail -3)"
  fi

  log "SECURITY: ungranted cross-service read is REFUSED, fail-closed, sticky"
  reset_arrays; LBL=(berm.enable=true berm.name=intruder berm.delivery=client "berm.file.d.from=shared-db/DB_PASSWORD")
  TMPFS=(/run/berm); CMD=(berm-client exec -- probe hold)
  run_app berm-itest-intruder >/dev/null
  local rc; rc="$(wait_exited berm-itest-intruder 15)"
  [ "$rc" != "0" ] && [ "$rc" != "-1" ] && pass "ungranted: intruder client exited nonzero (fetch refused)" || fail "ungranted: intruder client exited nonzero" "rc=$rc"
  assert_absent "ungranted: intruder never received the secret (no value in its logs)" "$(docker logs berm-itest-intruder 2>&1)" "$V_DBPASS"
  assert_contains "ungranted: daemon classified an ungranted_ref" "$(dlogs)" "ungranted_ref"
  assert_contains "ungranted: daemon alert names the intruder service" "$(dlogs)" "intruder"
  # Fleet still served: svca and webapp keep their secrets after the refusal.
  wait_running berm-itest-svca 5 && pass "ungranted: rest of the fleet still served (svca still up)" || fail "ungranted: fleet still served"
}

# ==========================================================================
# SECURITY SPINE: no-store / no-log / no-plaintext-on-disk (the trust argument)
# ==========================================================================
phase_no_leak() {
  log "SECURITY: no-store / no-log / no-plaintext-on-persistent-disk"
  local vals=("$V_SECRET_A" "$V_SECRET_B" "$V_FILEVAL" "$V_ENVTOKEN" "$V_SECRET_V" "$V_DBPASS" "$V_STALE_OLD")

  # 1. Daemon logs (docker logs) carry no secret value.
  local logs; logs="$(dlogs)"
  local v n leaks=0
  echo "-- grep: docker logs $DAEMON for each plaintext value --"
  for v in "${vals[@]}"; do
    n="$(printf '%s' "$logs" | grep -a -c -- "$v" || true)"
    echo "   value=<redacted> matches_in_daemon_log=$n"
    [ "$n" = "0" ] || leaks=$((leaks + 1))
  done
  assert_eq "no-leak: zero secret values in the daemon log" "0" "$leaks"

  # 2. The persisted ledger holds ciphertext hashes and names only, no value.
  local ledger; ledger="$(docker run --rm -v "$STATE_VOL":/s "$APPIMG" cat /s/ledger.json 2>/dev/null)"
  assert_contains "no-leak: the ledger exists and recorded injections (cipher_hash)" "$ledger" "cipher_hash"
  leaks=0
  echo "-- grep: /var/lib/berm/ledger.json for each plaintext value --"
  for v in "${vals[@]}"; do
    n="$(printf '%s' "$ledger" | grep -a -c -- "$v" || true)"
    echo "   value=<redacted> matches_in_ledger=$n"
    [ "$n" = "0" ] || leaks=$((leaks + 1))
  done
  assert_eq "no-leak: zero secret values in the persisted ledger" "0" "$leaks"

  # 3. The daemon's own filesystem (writable layer + image, excludes ro mounts
  #    for the key and ciphertext, which docker export does not include).
  local dexport="$OUT/daemon.fs"
  docker export "$DAEMON" > "$dexport" 2>/dev/null
  leaks=0
  echo "-- grep: 'docker export $DAEMON' (writable layer) for each plaintext value --"
  for v in "${vals[@]}"; do
    n="$(grep -a -c -- "$v" "$dexport" || true)"
    echo "   value=<redacted> matches_in_daemon_fs=$n"
    [ "$n" = "0" ] || leaks=$((leaks + 1))
  done
  assert_eq "no-leak: zero secret values in the daemon's writable layer" "0" "$leaks"

  # 4. The age key never appears inside any app container.
  local akeys; akeys="$(docker export berm-itest-svca 2>/dev/null | grep -a -c 'AGE-SECRET-KEY' || true)"
  assert_eq "no-leak: age secret key absent from an app container fs (svca)" "0" "$akeys"
  akeys="$(docker export berm-itest-svcenv 2>/dev/null | grep -a -c 'AGE-SECRET-KEY' || true)"
  assert_eq "no-leak: age secret key absent from an app container fs (svcenv)" "0" "$akeys"

  # 5. Delivered secret lives ONLY on tmpfs (statfs of the delivery path).
  assert_eq "no-leak: svca delivered secret sits on tmpfs, not persistent disk" "tmpfs" "$(dexec berm-itest-svca probe statfs /run/berm 2>/dev/null)"
  rm -f "$dexport"
}

# ==========================================================================
# FAILURE PATHS: each a validation error, skip-and-alert, never a silent empty
# delivery, never a fleet-wide break.
# ==========================================================================
# fail_client runs a client-mode app expected to be refused, asserts its client
# exits nonzero (not a silent empty success) and the daemon logs the class.
fail_client() { # name  class  desc  label...
  local name="$1" class="$2" desc="$3"; shift 3
  reset_arrays; LBL=("$@"); TMPFS=(/run/berm); CMD=(berm-client exec -- probe hold)
  run_app "$name" >/dev/null
  local rc; rc="$(wait_exited "$name" 15)"
  if [ "$rc" != "0" ] && [ "$rc" != "-1" ]; then pass "$desc: client refused (exit $rc, not a silent empty delivery)"; else fail "$desc: client refused" "rc=$rc logs: $(docker logs "$name" 2>&1 | tail -2)"; fi
  assert_contains "$desc: daemon classified $class" "$(dlogs)" "$class"
}

phase_failures() {
  log "FAILURE PATHS"
  fail_client berm-itest-envnoack env_no_acknowledge "env without acknowledge" \
    berm.enable=true berm.name=svcenv berm.delivery=client berm.env=ENVTOKEN
  fail_client berm-itest-unknown unknown_suffix "unknown berm suffix" \
    berm.enable=true berm.name=svca berm.delivery=client berm.file.a.from=SECRET_A berm.bogus=x
  fail_client berm-itest-conflict cross_prefix_conflict "cross-prefix conflict (different values)" \
    berm.enable=true berm.delivery=client berm.source=svca tagwright.secret.source=svcb
  fail_client berm-itest-missing missing_source "missing source" \
    berm.enable=true berm.name=missingsvc berm.delivery=client "berm.file.x.from=ghostsrc/K"
  fail_client berm-itest-baresdot wrong_ref_shape "bare-source ref against a dotenv source" \
    berm.enable=true berm.name=svca berm.delivery=client berm.file.x.from=svca
  fail_client berm-itest-keybin wrong_ref_shape "source/KEY ref against a binary source" \
    berm.enable=true berm.name=binblob berm.delivery=client "berm.file.x.from=binblob/K"

  # env under a non-client (volume) mechanism: caught by the loop's push path,
  # skip-and-alert (warning), the container keeps running with no secret.
  log "FAILURE: env delivery under the volume mechanism is refused"
  reset_arrays
  LBL=(berm.enable=true berm.name=svcv berm.delivery=volume berm.env=ENVTOKEN berm.env.acknowledge=true)
  CMD=(probe hold)
  run_app berm-itest-envvol >/dev/null
  wait_running berm-itest-envvol 12 || true
  sleep 1
  assert_contains "env-wrong-mechanism: daemon classified env_wrong_mechanism" "$(dlogs)" "env_wrong_mechanism"

  # Fleet still served after every failure.
  wait_running berm-itest-svca 5 && pass "failures: fleet still served (svca still up)" || fail "failures: fleet still served"
}

# ==========================================================================
# FAILURE PATH: sticky errors surface in the scheduled digest
# ==========================================================================
phase_sticky_digest() {
  log "FAILURE: sticky validation errors surface in the scheduled digest"
  # The intruder's ungranted_ref and the env-no-ack are sticky; the daemon runs
  # a 3s digest. Wait a couple of cycles and confirm the digest lists them.
  sleep 5
  local logs; logs="$(dlogs)"
  assert_contains "sticky-digest: digest reports standing sticky validation errors" "$logs" "Sticky validation errors"
  assert_contains "sticky-digest: the ungranted_ref stays visible in the digest" "$logs" "ungranted_ref"
}

# ==========================================================================
# FAILURE PATH: client timeout (forgotten berm-client wrapper)
# ==========================================================================
phase_client_timeout() {
  log "FAILURE: client-mode container that never runs berm-client -> timeout alert"
  reset_arrays
  LBL=(berm.enable=true berm.name=svca berm.delivery=client berm.file.a.from=SECRET_A)
  TMPFS=(/run/berm)
  CMD=(probe hold)   # NOTE: no berm-client wrapper, on purpose
  run_app berm-itest-forgot >/dev/null
  local fid; fid="$(docker inspect -f '{{.Id}}' berm-itest-forgot 2>/dev/null)"
  wait_running berm-itest-forgot 12 || true
  # BERM_CLIENT_TIMEOUT is 6s; wait past it.
  sleep 9
  local logs; logs="$(dlogs)"
  assert_contains "client-timeout: daemon fired a client fetch timeout alert" "$logs" "client fetch timeout"
  assert_contains "client-timeout: the alert names the offending container" "$logs" "$fid"
}

# ==========================================================================
# HAPPY PATH: volume mode end to end + waiter gates on the manifest
# ==========================================================================
phase_volume() {
  log "HAPPY: volume mode (tmpfs named volume, waiter gated on manifest)"

  # Before the volume-mode app starts, a waiter blocks on the manifest and must
  # time out: the ready signal is absent until the daemon populates the volume.
  docker run --rm --network none -v "$TMPFS_VOL":/run/berm:ro "$APPIMG" \
    probe waitfile /run/berm/manifest 2 >"$OUT/wait_before.txt" 2>&1
  local rc_before=$?
  assert_eq "volume: waiter blocks (times out) while the manifest is absent" "1" "$rc_before"
  assert_contains "volume: waiter reported timeout before injection" "$(cat "$OUT/wait_before.txt")" "timeout"

  # Start the volume-mode app. The daemon reacts to its start, writes the secret
  # and then the manifest into the shared tmpfs volume.
  reset_arrays
  LBL=(berm.enable=true berm.name=svcv berm.delivery=volume berm.volume=svcvvol berm.file.v.from=SECRET_V)
  VOLS=("$TMPFS_VOL:/run/berm")
  CMD=(probe hold)
  run_app berm-itest-svcv >/dev/null
  wait_running berm-itest-svcv 12 || fail "volume: app container running" "$(docker logs berm-itest-svcv 2>&1 | tail -3)"

  # After start, a waiter now sees the manifest and unblocks.
  docker run --rm --network none -v "$TMPFS_VOL":/run/berm:ro "$APPIMG" \
    probe waitfile /run/berm/manifest 8 >"$OUT/wait_after.txt" 2>&1
  local rc_after=$?
  assert_eq "volume: waiter unblocks once the daemon writes the manifest" "0" "$rc_after"
  assert_contains "volume: waiter reported ready after injection" "$(cat "$OUT/wait_after.txt")" "ready"

  assert_eq "volume: app reads its file secret byte-exact from the tmpfs volume" "$(sha_of "$V_SECRET_V")" "$(dexec berm-itest-svcv probe sha256 /run/berm/v 2>/dev/null)"
  assert_eq "volume: delivered secret sits on tmpfs" "tmpfs" "$(dexec berm-itest-svcv probe statfs /run/berm 2>/dev/null)"
  rm -f "$OUT/wait_before.txt" "$OUT/wait_after.txt"
}

# ==========================================================================
# ROTATION: staleness ledger flags a drifted source by ciphertext hash, no value
# ==========================================================================
phase_staleness() {
  log "ROTATION: staleness ledger flags a re-encrypted source, exposing no value"
  reset_arrays
  LBL=(berm.enable=true berm.name=svcstale berm.delivery=client berm.file.s.from=ROTKEY)
  TMPFS=(/run/berm); CMD=(berm-client exec -- probe hold)
  run_app berm-itest-svcstale >/dev/null
  wait_running berm-itest-svcstale 12 || { fail "staleness: svcstale app running" "$(docker logs berm-itest-svcstale 2>&1 | tail -3)"; return; }
  assert_eq "staleness: svcstale received the OLD secret" "$(sha_of "$V_STALE_OLD")" "$(dexec berm-itest-svcstale probe sha256 /run/berm/s 2>/dev/null)"
  # Give the daemon a moment to persist the injection into the ledger.
  sleep 1

  local before; before="$(docker exec -e BERM_SOURCES_ROOT=/var/lib/berm/sources "$DAEMON" berm stale --config /etc/berm/berm.yml --ledger /var/lib/berm/ledger.json 2>&1)"
  assert_contains "staleness: no drift before the source changes" "$before" "No drift"

  # Re-encrypt the source ciphertext with a CHANGED value (new ciphertext hash).
  local plain="$SRC/.svcstale.plain"
  printf 'ROTKEY=%s\n' "$V_STALE_NEW" > "$plain"
  local recip; recip="$(grep -oE 'age1[0-9a-z]+' "$KEYS/default.key" | head -1)"
  sops --config /dev/null -e --age "$recip" --input-type dotenv --output-type dotenv "$plain" > "$SRC/svcstale.sops.env"
  rm -f "$plain"

  local after; after="$(docker exec -e BERM_SOURCES_ROOT=/var/lib/berm/sources "$DAEMON" berm stale --config /etc/berm/berm.yml --ledger /var/lib/berm/ledger.json 2>&1)"
  assert_contains "staleness: berm stale reports drift after re-encryption" "$after" "drifted source"
  assert_contains "staleness: the drifted container is svcstale, marked changed" "$after" "svcstale"
  assert_absent "staleness: no OLD value exposed in the stale report" "$after" "$V_STALE_OLD"
  assert_absent "staleness: no NEW value exposed in the stale report" "$after" "$V_STALE_NEW"
}

# ==========================================================================
# REGRESSION: the shipped volume-mode turnkey compose must CONVERGE, not
# deadlock. The app is created up front by compose and its start is gated on a
# waiter that blocks on the manifest; the daemon must populate the created (not
# yet started) container's volume so the waiter clears and the app starts. This
# runs its own isolated compose stack, so the harness's main daemon is stopped
# first (two daemons on one host socket would both act on the app).
# ==========================================================================
phase_volume_compose() {
  log "REGRESSION: volume-mode turnkey compose converges (no create-vs-start deadlock)"
  if ! docker compose version >/dev/null 2>&1; then
    printf 'SKIP  volume-compose: docker compose not available\n'
    return
  fi
  docker stop "$DAEMON" >/dev/null 2>&1 || true

  local P=berm-itest-vc CF="$OUT/compose.yml"
  cat > "$CF" <<YML
services:
  berm:
    image: $IMG
    command: ["daemon","--config","/etc/berm/berm.yml","--socket","/run/berm-sock/berm.sock"]
    pid: host
    network_mode: none
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - $ITEST/berm.yml:/etc/berm/berm.yml:ro
      - $SRC:/var/lib/berm/sources:ro
      - $KEYS:/run/berm/age:ro
      - sock:/run/berm-sock
      - state:/var/lib/berm
      - appvol:/run/berm/volumes/vccompose
    environment:
      BERM_SOURCES_ROOT: /var/lib/berm/sources
      BERM_DEFAULT_DELIVERY: volume
  waiter:
    image: busybox:1.36
    command: ["sh","-c","until [ -f /run/berm/manifest ]; do sleep 0.2; done"]
    network_mode: none
    volumes:
      - appvol:/run/berm:ro
    depends_on:
      - berm
  app:
    image: $APPIMG
    command: ["probe","hold"]
    labels:
      berm.enable: "true"
      berm.name: "svcv"
      berm.delivery: "volume"
      berm.volume: "vccompose"
      berm.file.v.from: "SECRET_V"
    volumes:
      - appvol:/run/berm
    depends_on:
      waiter:
        condition: service_completed_successfully
volumes:
  sock:
  state:
  appvol:
    driver_opts:
      type: tmpfs
      device: tmpfs
YML

  # Bound the up: a deadlocked stack (the pre-fix behavior) hangs on the app's
  # depends_on forever, so timeout turns a regression into a fast, loud failure
  # (exit 124) instead of hanging the whole harness.
  timeout 75 docker compose -p "$P" -f "$CF" up -d >/dev/null 2>"$OUT/vc.err"
  local up_rc=$?
  assert_rc "volume-compose: 'compose up -d' converged (did not hang on the waiter)" "0" "$up_rc"
  local app_state waiter_code
  app_state="$(docker inspect -f '{{.State.Status}}' ${P}-app-1 2>/dev/null)"
  waiter_code="$(docker inspect -f '{{.State.ExitCode}}' ${P}-waiter-1 2>/dev/null)"
  assert_eq "volume-compose: the manifest waiter completed cleanly" "0" "$waiter_code"
  assert_eq "volume-compose: the gated app started" "running" "$app_state"
  if [ "$app_state" = "running" ]; then
    assert_eq "volume-compose: the app read its secret byte-exact from the shared tmpfs volume" \
      "$(sha_of "$V_SECRET_V")" "$(docker exec ${P}-app-1 probe sha256 /run/berm/v 2>/dev/null)"
  fi

  docker compose -p "$P" -f "$CF" down -v --timeout 20 >/dev/null 2>&1 || true
  rm -f "$CF" "$OUT/vc.err"
}

# --- main ------------------------------------------------------------------

main() {
  setup
  phase_client_happy
  phase_binary
  phase_isolation
  phase_grants
  phase_failures
  phase_sticky_digest
  phase_client_timeout
  phase_volume
  phase_staleness
  phase_no_leak
  phase_volume_compose

  log "RESULT"
  printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
  if [ "$FAIL" -ne 0 ]; then
    printf 'failed assertions:\n'
    printf '  - %s\n' "${FAILED_NAMES[@]}"
    return 1
  fi
  printf 'all integration assertions passed\n'
  return 0
}

main
RC=$?
exit "$RC"
