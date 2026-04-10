#!/usr/bin/env bash
set -euo pipefail
pkill -f /tmp/aegis-bin 2>/dev/null || true
env SUDO_USER=cellardoor /tmp/aegis-bin --db 'postgres://postgres:postgres@localhost/aegis?sslmode=disable' --policy /home/cellardoor/aegis/configs/default-policy.yaml >/home/cellardoor/policy-check.log 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
sleep 2
cat >/home/cellardoor/policy-check.json <<'JSON'
{"lang":"python","code":"print(\"policy works\")","timeout_ms":10000}
JSON
curl -s -X POST http://localhost:8080/v1/execute -H 'Content-Type: application/json' --data-binary @/home/cellardoor/policy-check.json