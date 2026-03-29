#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
DB_URL="${DB_URL:-postgres://postgres:postgres@localhost/aegis?sslmode=disable}"

resp="$(curl -fsS -X POST "$BASE_URL/v1/execute" -H "Content-Type: application/json" -d '{"lang":"bash","code":"echo audit-row","timeout_ms":10000}')"
echo "$resp"
execution_id="$(printf '%s' "$resp" | jq -r '.execution_id')"
[ -n "$execution_id" ] || { echo "missing execution_id" >&2; exit 1; }
row="$(psql "$DB_URL" -Atc "select lang || '|' || outcome || '|' || status from executions where execution_id = '$execution_id';")"
[ "$row" = "bash|success|completed" ] || { echo "unexpected audit row: $row" >&2; exit 1; }
