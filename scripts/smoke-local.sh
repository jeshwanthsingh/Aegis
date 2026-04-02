#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${BASE_URL:-http://localhost:8080}"
DB_URL="${DB_URL:-postgres://postgres:postgres@localhost/aegis?sslmode=disable}"
POLICY_PATH="${POLICY_PATH:-$REPO_DIR/configs/default-policy.yaml}"
ASSETS_DIR="${ASSETS_DIR:-$REPO_DIR/assets}"
ROOTFS_PATH="${ROOTFS_PATH:-${AEGIS_ROOTFS_PATH:-}}"
ORCH_BIN="${ORCH_BIN:-/tmp/aegis-bin}"
LOG_FILE="${LOG_FILE:-/tmp/aegis-smoke-local.log}"
FAILURES=0
A_STARTED=0

pass() {
  printf 'PASS %s\n' "$1"
}

fail() {
  printf 'FAIL %s' "$1"
  if [ "$#" -gt 1 ] && [ -n "$2" ]; then
    printf ': %s' "$2"
  fi
  printf '\n' >&2
  FAILURES=$((FAILURES + 1))
}

as_root() {
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    "$@"
  fi
}

execute_json() {
  local payload="$1"
  curl -fsS -X POST "$BASE_URL/v1/execute" -H 'Content-Type: application/json' -d "$payload"
}

cleanup() {
  if [ "$A_STARTED" -eq 1 ]; then
    sudo pkill -f "$ORCH_BIN" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

"$REPO_DIR/scripts/preflight.sh" >/dev/null

if ! command -v ss >/dev/null 2>&1; then
  fail "port check" "ss not found"
  exit 1
fi

if ss -ltn '( sport = :8080 )' | grep -q ':8080'; then
  if curl -fsS "$BASE_URL/health" >/dev/null; then
    pass "boot (reused existing orchestrator)"
  else
    fail "boot" "port 8080 already in use and existing service did not pass health"
    exit 1
  fi
else
  if [ ! -x "$ORCH_BIN" ]; then
    if command -v go >/dev/null 2>&1; then
      go build -buildvcs=false -o "$ORCH_BIN" "$REPO_DIR/cmd/orchestrator"
    elif [ -x "$HOME/local/go/bin/go" ]; then
      "$HOME/local/go/bin/go" build -buildvcs=false -o "$ORCH_BIN" "$REPO_DIR/cmd/orchestrator"
    else
      fail "boot" "orchestrator binary missing at $ORCH_BIN and go not found"
      exit 1
    fi
  fi

  cmd=(sudo env "PATH=$PATH:/sbin:/usr/sbin" SUDO_USER="${SUDO_USER:-$(id -un)}" "$ORCH_BIN" \
    --db "$DB_URL" \
    --policy "$POLICY_PATH" \
    --assets-dir "$ASSETS_DIR")
  if [ -n "$ROOTFS_PATH" ]; then
    cmd+=(--rootfs-path "$ROOTFS_PATH")
  fi
  "${cmd[@]}" >"$LOG_FILE" 2>&1 &
  A_STARTED=1
  sleep 3

  if curl -fsS "$BASE_URL/health" >/dev/null; then
    pass "boot"
  else
    fail "boot" "health check failed after orchestrator start"
  fi
fi

bash_resp="$(execute_json '{"lang":"bash","code":"echo SMOKE_LOCAL_BASH","timeout_ms":10000}' 2>/dev/null || true)"
if RESP_JSON="$bash_resp" python3 - <<'PY'
import json, os
resp = json.loads(os.environ['RESP_JSON'])
assert resp.get('exit_code', 0) == 0, resp
assert 'SMOKE_LOCAL_BASH' in resp.get('stdout', ''), resp
PY
then
  pass "bash execute"
else
  fail "bash execute" "$bash_resp"
fi

python_resp="$(execute_json '{"lang":"python","code":"print(\"SMOKE_LOCAL_PYTHON\")","timeout_ms":10000}' 2>/dev/null || true)"
if RESP_JSON="$python_resp" python3 - <<'PY'
import json, os
resp = json.loads(os.environ['RESP_JSON'])
assert resp.get('exit_code', 0) == 0, resp
assert 'SMOKE_LOCAL_PYTHON' in resp.get('stdout', ''), resp
PY
then
  pass "python execute"
else
  fail "python execute" "$python_resp"
fi

sleep 2
leftover_files="$(find /tmp/aegis -maxdepth 1 \( -name 'scratch-*.ext4' -o -name 'fc-*.sock' -o -name 'vsock-*.sock' \) 2>/dev/null | wc -l | tr -d ' ')"
tap_count="$(as_root ip -o link show 2>/dev/null | awk -F': ' '/tap-[[:alnum:]-]+/ {count++} END {print count+0}')"
cgroup_count="$(find /sys/fs/cgroup/aegis -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
if [ "$leftover_files" = "0" ] && [ "$tap_count" = "0" ] && [ "$cgroup_count" = "0" ]; then
  pass "teardown verification"
else
  fail "teardown verification" "leftover_files=$leftover_files tap_count=$tap_count cgroup_count=$cgroup_count"
fi

printf '\nSummary:\n'
printf '  orchestrator log: %s\n' "$LOG_FILE"

if [ "$FAILURES" -ne 0 ]; then
  printf 'smoke-local failed with %d failure(s)\n' "$FAILURES" >&2
  exit 1
fi

printf 'smoke-local passed\n'
