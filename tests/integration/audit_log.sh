#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
DB_URL="${DB_URL:-postgres://postgres:postgres@localhost/aegis?sslmode=disable}"

resp="$(curl -fsS -X POST "$BASE_URL/v1/execute" -H "Content-Type: application/json" -d '{"lang":"bash","code":"echo audit-row","timeout_ms":10000}')"
echo "$resp"
execution_id="$(printf '%s' "$resp" | jq -r '.execution_id')"
stdout="$(printf '%s' "$resp" | jq -r '.stdout // empty')"
stderr="$(printf '%s' "$resp" | jq -r '.stderr // empty')"
exit_code="$(printf '%s' "$resp" | jq -r '.exit_code // 0')"

[ -n "$execution_id" ] || { echo "missing execution_id" >&2; exit 1; }
[ "$stdout" = "audit-row" ] || { echo "unexpected stdout: $stdout" >&2; [ -z "$stderr" ] || echo "stderr: $stderr" >&2; exit 1; }

expected_outcome="success"
if [ "$exit_code" != "0" ]; then
  expected_outcome="completed_nonzero"
fi

row="$(psql "$DB_URL" -Atc "select lang || '|' || outcome || '|' || status || '|' || exit_code from executions where execution_id = '$execution_id';")"
expected_row="bash|$expected_outcome|completed|$exit_code"
[ "$row" = "$expected_row" ] || { echo "unexpected audit row: $row" >&2; echo "expected audit row: $expected_row" >&2; exit 1; }
