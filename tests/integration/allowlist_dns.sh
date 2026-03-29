#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"

echo "================================================"
echo " AEGIS - Allowlist DNS Smoke Test"
echo "================================================"

health="$(curl -fsS "$BASE_URL/health")"
echo "$health"

allowed_payload='{"lang":"python","code":"import socket\nip = socket.gethostbyname(\"pypi.org\")\ns = socket.create_connection((ip, 443), timeout=5)\ns.close()\nprint(\"ALLOWED_DNS=\" + ip)\nprint(\"ALLOWED_CONNECT=ok\")\n","timeout_ms":25000}'
denied_payload='{"lang":"python","code":"import socket\ntry:\n    socket.gethostbyname(\"example.com\")\nexcept Exception:\n    print(\"DENIED_DNS=ok\")\nelse:\n    raise SystemExit(\"unexpectedly resolved example.com\")\n","timeout_ms":25000}'

run_and_assert() {
  local label="$1"
  local payload="$2"
  local expected="$3"
  echo
  echo "$label"
  echo "----------------------------------------------"
  local resp
  resp="$(curl -fsS -X POST "$BASE_URL/v1/execute" -H "Content-Type: application/json" -d "$payload")"
  echo "$resp"
  RESP_JSON="$resp" EXPECTED_TEXT="$expected" python3 - <<'PY'
import json
import os
import sys
resp = json.loads(os.environ["RESP_JSON"])
expected = os.environ["EXPECTED_TEXT"]
stdout = resp.get("stdout", "")
stderr = resp.get("stderr", "")
error = resp.get("error", "")
exit_code = resp.get("exit_code", 0)
if error:
    raise SystemExit(f"unexpected API error: {error}")
if exit_code != 0:
    raise SystemExit(f"unexpected exit_code {exit_code}; stderr={stderr!r}; stdout={stdout!r}")
if expected not in stdout:
    raise SystemExit(f"missing expected marker {expected!r}; stdout={stdout!r}; stderr={stderr!r}")
PY
}

run_and_assert "Step 1: Allowed preset hostname resolves and opens 443" "$allowed_payload" "ALLOWED_CONNECT=ok"
run_and_assert "Step 2: Non-allowlisted hostname does not resolve" "$denied_payload" "DENIED_DNS=ok"

echo
echo "allowlist DNS smoke test passed"