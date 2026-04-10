#!/usr/bin/env bash
set -euo pipefail
pkill -f aegis-bin 2>/dev/null || true
env PATH=$PATH SUDO_USER=cellardoor /tmp/aegis-bin --db 'postgres://postgres:postgres@localhost/aegis?sslmode=disable' --policy /home/cellardoor/aegis/configs/default-policy.yaml >/home/cellardoor/stream-test.log 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
sleep 2
printf "=== TEST 1 ===\n"
/tmp/aegis-cli run --lang python --code "print(1)"
printf "\n=== TEST 2 ===\n"
/tmp/aegis-cli run --lang python --code $'import time\nfor i in range(5):\n    print(f"line {i}", flush=True)\n    time.sleep(0.5)\n' --stream --timeout 15000
printf "\n=== TEST 3 ===\n"
curl -sN http://localhost:8080/v1/execute/stream -H 'Content-Type: application/json' -d '{"lang":"bash","code":"for i in 1 2 3; do echo $i; sleep 0.3; done","timeout_ms":10000}'