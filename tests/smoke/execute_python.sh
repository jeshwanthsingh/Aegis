#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
resp="$(curl -fsS -X POST "$BASE_URL/v1/execute" -H "Content-Type: application/json" -d '{"lang":"python","code":"print(1)","timeout_ms":10000}')"
echo "$resp"
error="$(printf '%s' "$resp" | jq -r '.error // empty')"
stdout="$(printf '%s' "$resp" | jq -r '.stdout // empty')"
exit_code="$(printf '%s' "$resp" | jq -r '.exit_code // 0')"
[ -z "$error" ] || { echo "unexpected error: $error" >&2; exit 1; }
[ "$stdout" = "1" ] || { echo "unexpected stdout: $stdout" >&2; exit 1; }
[ "$exit_code" = "0" ] || { echo "unexpected exit_code: $exit_code" >&2; exit 1; }
