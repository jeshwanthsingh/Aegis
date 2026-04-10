#!/usr/bin/env bash
set -euo pipefail
printf "=== BUILD GUEST ===\n"
cd /home/cellardoor/aegis/guest-runner
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 /home/cellardoor/local/go/bin/go build -buildvcs=false -a -o guest-runner .
printf "\n=== BAKE GUEST ===\n"
mount /home/cellardoor/aegis/assets/alpine-base.ext4 /mnt/rootfs
cp guest-runner /mnt/rootfs/usr/local/bin/guest-runner
umount /mnt/rootfs
printf "\n=== BUILD ORCHESTRATOR ===\n"
cd /home/cellardoor/aegis
/home/cellardoor/local/go/bin/go build -buildvcs=false -o /tmp/aegis-bin ./cmd/orchestrator
pkill -f aegis-bin 2>/dev/null || true
env SUDO_USER=cellardoor /tmp/aegis-bin --db 'postgres://postgres:postgres@localhost/aegis?sslmode=disable' --policy /home/cellardoor/aegis/configs/default-policy.yaml >/home/cellardoor/p2p3-test.log 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
sleep 2
printf "\n=== CLI TEST ===\n"
/tmp/aegis-cli run --lang python --code "import sys; sys.exit(1)" || true
printf "\n=== AUDIT TEST ===\n"
PGPASSWORD=postgres psql -h localhost -U postgres -d aegis -c "SELECT outcome, exit_code FROM executions ORDER BY created_at DESC LIMIT 3;"