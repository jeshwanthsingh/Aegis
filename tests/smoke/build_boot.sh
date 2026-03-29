#!/usr/bin/env bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$(pwd)/assets}"

[ -x /tmp/aegis-bin ] || { echo "/tmp/aegis-bin missing or not executable" >&2; exit 1; }
command -v firecracker >/dev/null 2>&1 || { echo "firecracker not on PATH" >&2; exit 1; }
[ -f "$ASSETS_DIR/vmlinux" ] || { echo "missing kernel image at $ASSETS_DIR/vmlinux" >&2; exit 1; }
[ -f "$ASSETS_DIR/alpine-base.ext4" ] || { echo "missing rootfs image at $ASSETS_DIR/alpine-base.ext4" >&2; exit 1; }

"$(dirname "$0")/health.sh"
