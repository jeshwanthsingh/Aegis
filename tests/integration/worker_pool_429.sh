#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
payload='{"lang":"bash","code":"sleep 5; echo worker","timeout_ms":15000}'

for i in 1 2 3 4 5 6 7 8; do
  (
    code="$(
      curl -sS \
        -o "$tmpdir/$i.body" \
        -D "$tmpdir/$i.headers" \
        -w '%{http_code}' \
        -X POST "$BASE_URL/v1/execute" \
        -H "Content-Type: application/json" \
        -d "$payload" || true
    )"
    printf '%s\n' "$code" > "$tmpdir/$i.code"
  ) &
done
wait || true

for f in "$tmpdir"/*.code; do
  echo "=== $f ==="
  cat "$f"
done

count_429_matches="$(grep -l '^HTTP/.* 429' "$tmpdir"/*.headers 2>/dev/null || true)"
count_429="$(printf '%s\n' "$count_429_matches" | sed '/^$/d' | wc -l | tr -d ' ')"
[ "$count_429" -ge 1 ] || {
  echo "expected at least one 429 response" >&2
  for f in "$tmpdir"/*.headers; do
    echo "=== $f ===" >&2
    cat "$f" >&2
  done
  exit 1
}

header_dump="$(cat "$tmpdir"/*.headers | tr -d '\r')"
printf '%s\n' "$header_dump" | grep -qi '^Retry-After: 5$' || {
  echo "missing Retry-After header on overflow response" >&2
  printf '%s\n' "$header_dump" >&2
  exit 1
}

echo "worker pool overflow produced $count_429 429 response(s)"
