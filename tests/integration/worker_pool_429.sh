#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
hold_payload='{"lang":"bash","code":"sleep 5","timeout_ms":8000}'
overflow_payload='{"lang":"bash","code":"echo overflow","timeout_ms":8000}'

for i in 1 2 3 4 5; do
  (
    curl -sS \
      -o "$tmpdir/hold-$i.body" \
      -D "$tmpdir/hold-$i.headers" \
      -w '%{http_code}' \
      -X POST "$BASE_URL/v1/execute" \
      -H "Content-Type: application/json" \
      -d "$hold_payload" > "$tmpdir/hold-$i.code" || true
  ) &
done

sleep 1

curl -sS \
  -o "$tmpdir/overflow.body" \
  -D "$tmpdir/overflow.headers" \
  -w '%{http_code}' \
  -X POST "$BASE_URL/v1/execute" \
  -H "Content-Type: application/json" \
  -d "$overflow_payload" > "$tmpdir/overflow.code" || true

overflow_code="$(cat "$tmpdir/overflow.code")"
header_dump="$(tr -d '\r' < "$tmpdir/overflow.headers")"

echo "overflow_code=$overflow_code"
printf '%s\n' "$header_dump"

[ "$overflow_code" = "429" ] || {
  echo "expected overflow request to return 429" >&2
  echo "=== overflow body ===" >&2
  cat "$tmpdir/overflow.body" >&2
  exit 1
}

printf '%s\n' "$header_dump" | grep -qi '^Retry-After: 5$' || {
  echo "missing Retry-After header on overflow response" >&2
  exit 1
}

wait || true
echo "worker pool overflow produced 429 as expected"
