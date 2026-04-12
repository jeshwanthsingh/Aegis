#!/usr/bin/env bash
set -euo pipefail
rm -f /tmp/aegis-cli
cd /home/cellardoor/aegis
printf "=== BUILD CLI ===\n"
/home/cellardoor/local/go/bin/go build -buildvcs=false -o /tmp/aegis-cli ./cmd/aegis-cli
printf "\n=== BUILD GUEST ===\n"
cd /home/cellardoor/aegis/guest-runner
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 /home/cellardoor/local/go/bin/go build -buildvcs=false -a -o guest-runner .
printf "\n=== BAKE GUEST ===\n"
mount /home/cellardoor/aegis/assets/alpine-base.ext4 /mnt/rootfs
cp guest-runner /mnt/rootfs/usr/local/bin/guest-runner
umount /mnt/rootfs
