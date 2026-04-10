#!/usr/bin/env bash
set -euo pipefail
cd /home/cellardoor/aegis/guest-runner
printf "=== BUILD GUEST ===\n"
/home/cellardoor/local/go/bin/go build -buildvcs=false -a -o guest-runner .
printf "\n=== BAKE GUEST ===\n"
mount /home/cellardoor/aegis/assets/alpine-base.ext4 /mnt/rootfs
cp guest-runner /mnt/rootfs/usr/local/bin/guest-runner
umount /mnt/rootfs