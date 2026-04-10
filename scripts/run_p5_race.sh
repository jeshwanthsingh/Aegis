#!/usr/bin/env bash
set -euo pipefail
pkill -f aegis-bin 2>/dev/null || true
env SUDO_USER=cellardoor /tmp/aegis-bin --db 'postgres://postgres:postgres@localhost/aegis?sslmode=disable' --policy /home/cellardoor/aegis/configs/default-policy.yaml >/home/cellardoor/p5-race.log 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
sleep 2
for i in 1 2 3 4 5; do
  curl -s -X POST http://localhost:8080/v1/execute \
    -H 'Content-Type: application/json' \
    -d '{"lang":"bash","code":"echo hello","timeout_ms":10000}' | python3 -c 'import sys, json; d=json.load(sys.stdin); print(d.get("stdout") or d.get("error"))'
done