#!/usr/bin/env bash
set -euo pipefail
cd /home/cellardoor/aegis
/home/cellardoor/local/go/bin/go build -buildvcs=false -o /tmp/aegis-cli ./cmd/aegis-cli
pkill -f /tmp/aegis-bin 2>/dev/null || true
env SUDO_USER=cellardoor /tmp/aegis-bin --db 'postgres://postgres:postgres@localhost/aegis?sslmode=disable' --policy /home/cellardoor/aegis/configs/default-policy.yaml >/home/cellardoor/aegis-cli-test.log 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
sleep 2
printf "=== TEST 1 ===\n"
/tmp/aegis-cli run --lang python --code "print('hello from cli')" || true
printf "\n=== TEST 2 ===\n"
/tmp/aegis-cli run --lang bash --code "echo 'bash works'" || true
printf "\n=== TEST 3 ===\n"
printf "print('from file')\n" > /tmp/test.py
/tmp/aegis-cli run --lang python --file /tmp/test.py || true
printf "\n=== TEST 4 ===\n"
/tmp/aegis-cli health || true