#!/usr/bin/env bash
set -euo pipefail
pkill -f /tmp/aegis-bin 2>/dev/null || true
env SUDO_USER=cellardoor /tmp/aegis-bin --db 'postgres://postgres:postgres@localhost/aegis?sslmode=disable' --policy /home/cellardoor/aegis/configs/default-policy.yaml >/home/cellardoor/retry-after-test.log 2>&1 &
pid=$!
cleanup() {
  kill $pid 2>/dev/null || true
  jobs -p | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT
sleep 2
cat >/home/cellardoor/hold.json <<'JSON'
{"lang":"bash","code":"sleep 8","timeout_ms":10000}
JSON
cat >/home/cellardoor/once.json <<'JSON'
{"lang":"python","code":"print(1)","timeout_ms":5000}
JSON
for i in 1 2 3 4 5; do
  curl -s -X POST http://localhost:8080/v1/execute -H 'Content-Type: application/json' --data-binary @/home/cellardoor/hold.json >/home/cellardoor/hold-$i.out &
done
for _ in $(seq 1 20); do
  health=$(curl -s http://localhost:8080/health || true)
  case "$health" in
    *'"worker_slots_available":0'*) break ;;
  esac
  sleep 1
done
curl -si -X POST http://localhost:8080/v1/execute -H 'Content-Type: application/json' --data-binary @/home/cellardoor/once.json