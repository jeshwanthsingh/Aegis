#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
FAILURES=0

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

check_contained_nonzero() {
  local label="$1"
  local payload="$2"
  local resp
  if ! resp="$(execute_json "$payload")"; then
    fail "$label" "request failed"
    return
  fi
  if RESP_JSON="$resp" python3 - <<'PY'
import json, os
resp = json.loads(os.environ['RESP_JSON'])
if resp.get('error') and resp['error'] != 'timeout':
    raise SystemExit(f"unexpected API error: {resp['error']}")
if resp.get('error') == 'timeout':
    raise SystemExit(0)
if resp.get('exit_code', 0) == 0:
    raise SystemExit('expected nonzero exit_code or timeout containment')
PY
  then
    pass "$label"
  else
    fail "$label" "$resp"
  fi
}

check_truncated_output() {
  local label="$1"
  local payload="$2"
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
if not resp.get('output_truncated'):
    raise SystemExit('expected output_truncated=true')
PY
  then
    pass "$label"
  else
    fail "$label" "$resp"
  fi
}

check_health_after_abuse() {
  local resp
  if ! resp="$(curl -fsS "$BASE_URL/health")"; then
    fail "post-abuse health" "health endpoint request failed"
    return
  fi
  if HEALTH_JSON="$resp" python3 - <<'PY'
import json, os
resp = json.loads(os.environ['HEALTH_JSON'])
if resp.get('status') != 'ok':
    raise SystemExit('status not ok')
PY
  then
    pass "post-abuse health"
  else
    fail "post-abuse health" "$resp"
  fi
}

check_contained_nonzero "fork bomb (bash)" '{"lang":"bash","code":"for i in $(seq 1 256); do bash -c \"sleep 30\" & done\nwait","timeout_ms":10000}'
check_contained_nonzero "infinite loop" '{"lang":"python","code":"while True: pass","timeout_ms":3000}'
check_contained_nonzero "memory bomb" '{"lang":"python","code":"x = b\"x\" * 10**9\nprint(len(x))","timeout_ms":10000}'
check_truncated_output "huge stdout" '{"lang":"python","code":"import sys\nsys.stdout.write(\"A\" * 70000)","timeout_ms":10000}'
check_contained_nonzero "process explosion" '{"lang":"python","code":"import os, sys, time\nchildren = []\nwhile True:\n    try:\n        pid = os.fork()\n    except OSError:\n        sys.exit(1)\n    if pid == 0:\n        time.sleep(30)\n        os._exit(0)\n    children.append(pid)","timeout_ms":10000}'
check_health_after_abuse

if [ "$FAILURES" -ne 0 ]; then
  printf 'abuse.sh failed with %d failure(s)\n' "$FAILURES" >&2
  exit 1
fi

printf 'abuse.sh passed\n'
