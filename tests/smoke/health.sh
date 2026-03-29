#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"

resp="$(curl -fsS "$BASE_URL/health")"
echo "$resp"
status="$(printf '%s' "$resp" | jq -r '.status // "down"')"
[ "$status" = "ok" ] || { echo "expected health status ok, got $status" >&2; exit 1; }
