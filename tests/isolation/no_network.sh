#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
resp="$(curl -fsS -X POST "$BASE_URL/v1/execute" -H "Content-Type: application/json" -d '{"lang":"bash","code":"timeout 3 wget -qO- http://example.com || echo blocked","timeout_ms":10000}')"
echo "$resp"
