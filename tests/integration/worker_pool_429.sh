#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
payload='{"lang":"bash","code":"sleep 2; echo worker","timeout_ms":15000}'

for i in 1 2 3 4 5 6; do
  (
    curl -sS -o "$tmpdir/$i.body" -D "$tmpdir/$i.headers"       -X POST "$BASE_URL/v1/execute"       -H "Content-Type: application/json"       -d "$payload" >/dev/null
  ) &
done
wait

count_429="$(grep -l '^HTTP/.* 429' "$tmpdir"/*.headers 2>/dev/null | wc -l | tr -d ' ')"
[ "$count_429" -ge 1 ] || { echo "expected at least one 429 response" >&2; exit 1; }
grep -q '^Retry-After: 5' "$tmpdir"/*.headers || { echo "missing Retry-After header on overflow response" >&2; exit 1; }
echo "worker pool overflow produced $count_429 429 response(s)"
