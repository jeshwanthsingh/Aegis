#!/usr/bin/env bash
set -euo pipefail
cd /home/cellardoor/aegis/guest-runner
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 /home/cellardoor/local/go/bin/go build -buildvcs=false -a -o guest-runner .
mount /home/cellardoor/aegis/assets/alpine-base.ext4 /mnt/rootfs
cp guest-runner /mnt/rootfs/usr/local/bin/guest-runner
umount /mnt/rootfs
cd /home/cellardoor/aegis
/home/cellardoor/local/go/bin/go build -buildvcs=false -o /tmp/aegis-bin ./cmd/orchestrator
pkill -f aegis-bin 2>/dev/null || true
env SUDO_USER=cellardoor /tmp/aegis-bin --db 'postgres://postgres:postgres@localhost/aegis?sslmode=disable' --policy /home/cellardoor/aegis/configs/default-policy.yaml >/home/cellardoor/p5-race.log 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
sleep 2
for i in $(seq 1 10); do
  curl -s -X POST http://localhost:8080/v1/execute \
    -H 'Content-Type: application/json' \
    -d '{"lang":"bash","code":"echo hello","timeout_ms":10000}' | python3 -c 'import sys, json; d=json.load(sys.stdin); print(d.get("stdout") or d.get("error"))'
done