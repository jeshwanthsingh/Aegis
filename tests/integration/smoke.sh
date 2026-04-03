#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TMPDIR_SMOKE="$(mktemp -d)"
FAILURES=0
trap 'rm -rf "$TMPDIR_SMOKE"' EXIT

as_root() {
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    "$@"
  fi
}

pass() {
  printf 'PASS %s\n' "$1"
}

fail() {
  printf 'FAIL %s\n' "$1"
  if [ "$#" -gt 1 ] && [ -n "$2" ]; then
    printf '%s\n' "$2" >&2
  fi
  FAILURES=$((FAILURES + 1))
}

execute_json() {
  local payload="$1"
  curl -fsS -X POST "$BASE_URL/v1/execute" -H 'Content-Type: application/json' -d "$payload"
}

check_health() {
  local resp
  if ! resp="$(curl -fsS "$BASE_URL/health")"; then
    fail "health" "health endpoint request failed"
    return
  fi
  if HEALTH_JSON="$resp" python3 - <<'PY'
import json, os, sys
resp = json.loads(os.environ['HEALTH_JSON'])
if resp.get('status') != 'ok':
    raise SystemExit('status not ok')
if resp.get('worker_slots_total') != 5:
    raise SystemExit(f"unexpected worker_slots_total={resp.get('worker_slots_total')}")
PY
  then
    pass "health"
  else
    fail "health" "$resp"
  fi
}

check_execute_success() {
  local label="$1"
  local payload="$2"
  local marker="$3"
  local resp
  if ! resp="$(execute_json "$payload")"; then
    fail "$label" "request failed"
    return
  fi
  if RESP_JSON="$resp" EXPECTED_MARKER="$marker" python3 - <<'PY'
import json, os
resp = json.loads(os.environ['RESP_JSON'])
marker = os.environ['EXPECTED_MARKER']
if resp.get('error'):
    raise SystemExit(f"unexpected API error: {resp['error']}")
if resp.get('exit_code', 0) != 0:
    raise SystemExit(f"unexpected exit_code={resp.get('exit_code')} stderr={resp.get('stderr','')!r}")
if marker not in resp.get('stdout', ''):
    raise SystemExit(f"missing marker {marker!r} stdout={resp.get('stdout','')!r} stderr={resp.get('stderr','')!r}")
PY
  then
    pass "$label"
  else
    fail "$label" "$resp"
  fi
}

check_timeout() {
  local label="timeout enforcement"
  local payload='{"lang":"bash","code":"sleep 30","timeout_ms":1000}'
  local resp
  if ! resp="$(execute_json "$payload")"; then
    fail "$label" "request failed"
    return
  fi
  if RESP_JSON="$resp" python3 - <<'PY'
import json, os
resp = json.loads(os.environ['RESP_JSON'])
if resp.get('error'):
    raise SystemExit(f"unexpected API error: {resp['error']}")
if resp.get('exit_code') != -1:
    raise SystemExit(f"expected exit_code -1, got {resp.get('exit_code')}")
if 'execution timeout' not in resp.get('stderr', ''):
    raise SystemExit(f"missing timeout stderr: {resp.get('stderr','')!r}")
PY
  then
    pass "$label"
  else
    fail "$label" "$resp"
  fi
}

check_concurrency_and_429() {
  local label="concurrent execution + 429"
  local hold_payload='{"lang":"bash","code":"sleep 6","timeout_ms":10000}'
  local overflow_payload='{"lang":"bash","code":"echo overflow","timeout_ms":10000}'

  for i in 1 2 3 4 5; do
    (
      curl -sS \
        -o "$TMPDIR_SMOKE/hold-$i.body" \
        -D "$TMPDIR_SMOKE/hold-$i.headers" \
        -w '%{http_code}' \
        -X POST "$BASE_URL/v1/execute" \
        -H 'Content-Type: application/json' \
        -d "$hold_payload" > "$TMPDIR_SMOKE/hold-$i.code" || true
    ) &
  done

  sleep 1

  curl -sS \
    -o "$TMPDIR_SMOKE/overflow.body" \
    -D "$TMPDIR_SMOKE/overflow.headers" \
    -w '%{http_code}' \
    -X POST "$BASE_URL/v1/execute" \
    -H 'Content-Type: application/json' \
    -d "$overflow_payload" > "$TMPDIR_SMOKE/overflow.code" || true

  local overflow_code
  overflow_code="$(cat "$TMPDIR_SMOKE/overflow.code")"
  local header_dump
  header_dump="$(tr -d '\r' < "$TMPDIR_SMOKE/overflow.headers")"

  local ok=1
  if [ "$overflow_code" != "429" ]; then
    ok=0
  fi
  if ! printf '%s\n' "$header_dump" | grep -qi '^Retry-After: 5$'; then
    ok=0
  fi

  wait || true

  for i in 1 2 3 4 5; do
    local body
    body="$(cat "$TMPDIR_SMOKE/hold-$i.body")"
    if ! RESP_JSON="$body" python3 - <<'PY'
import json, os
resp = json.loads(os.environ['RESP_JSON'])
if resp.get('error'):
    raise SystemExit(resp['error'])
if resp.get('exit_code', 0) != 0:
    raise SystemExit(f"exit_code={resp.get('exit_code')} stderr={resp.get('stderr','')!r}")
PY
    then
      ok=0
    fi
  done

  if [ "$ok" -eq 1 ]; then
    pass "$label"
  else
    fail "$label" "overflow_code=$overflow_code headers=$header_dump"
  fi
}

check_teardown() {
  local label="teardown verification"
  sleep 2
  local leftover_files tap_count cgroup_count
  if [ -d /tmp/aegis ]; then
    leftover_files="$( (find /tmp/aegis -maxdepth 1 \( -name 'scratch-*.ext4' -o -name 'fc-*.sock' -o -name 'vsock-*.sock' \) 2>/dev/null || true) | wc -l | tr -d ' ')"
  else
    leftover_files="0"
  fi
  tap_count="$( (as_root ip -o link show 2>/dev/null || true) | awk -F': ' '/tap-[[:alnum:]-]+/ {count++} END {print count+0}')"
  if [ -d /sys/fs/cgroup/aegis ]; then
    cgroup_count="$( (find /sys/fs/cgroup/aegis -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true) | wc -l | tr -d ' ')"
  else
    cgroup_count="0"
  fi

  if [ "$leftover_files" = "0" ] && [ "$tap_count" = "0" ] && [ "$cgroup_count" = "0" ]; then
    pass "$label"
  else
    fail "$label" "leftover_files=$leftover_files tap_count=$tap_count cgroup_count=$cgroup_count"
  fi
}

check_health
check_execute_success "bash execute" '{"lang":"bash","code":"echo SMOKE_BASH","timeout_ms":10000}' 'SMOKE_BASH'
check_execute_success "python execute" '{"lang":"python","code":"print(\"SMOKE_PYTHON\")","timeout_ms":10000}' 'SMOKE_PYTHON'
check_timeout
check_concurrency_and_429
check_teardown
check_execute_success "allowlist DNS resolve" '{"lang":"python","code":"import socket\ninfos = socket.getaddrinfo(\"pypi.org\", 443, type=socket.SOCK_STREAM)\nips = []\nfor family, socktype, proto, canonname, sockaddr in infos:\n    ip = sockaddr[0]\n    if ip not in ips:\n        ips.append(ip)\nif not ips:\n    raise SystemExit(\"no addresses resolved\")\nprint(\"ALLOWED_DNS=\" + \",\".join(ips))\n","timeout_ms":25000}' 'ALLOWED_DNS='
check_execute_success "allowlist DNS deny" '{"lang":"python","code":"import socket\ntry:\n    socket.gethostbyname(\"example.com\")\nexcept Exception:\n    print(\"DENIED_DNS=ok\")\nelse:\n    raise SystemExit(\"unexpectedly resolved example.com\")\n","timeout_ms":25000}' 'DENIED_DNS=ok'

if [ "$FAILURES" -ne 0 ]; then
  printf 'smoke.sh failed with %d failure(s)\n' "$FAILURES" >&2
  exit 1
fi

printf 'smoke.sh passed\n'
