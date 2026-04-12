#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOTFS_PATH="${ROOTFS_PATH:-$REPO_DIR/assets/alpine-base.ext4}"
GUEST_RUNNER_BIN="${GUEST_RUNNER_BIN:-$REPO_DIR/guest-runner/guest-runner}"
GO_BIN="${GO_BIN:-}"
META_JSON="$(mktemp)"
DEBUGFS_CMDS="$(mktemp)"
cleanup() {
  rm -f "$META_JSON" "$DEBUGFS_CMDS"
}
trap cleanup EXIT

find_go() {
  if [ -n "$GO_BIN" ] && [ -x "$GO_BIN" ]; then
    printf '%s
' "$GO_BIN"
  elif command -v go >/dev/null 2>&1; then
    command -v go
  elif [ -x "$HOME/local/go/bin/go" ]; then
    printf '%s
' "$HOME/local/go/bin/go"
  else
    return 1
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing prerequisite: %s
' "$1" >&2
    exit 1
  }
}

need_cmd debugfs
need_cmd sha256sum
GO_BIN="$(find_go)" || { echo 'missing go toolchain' >&2; exit 1; }

(
  cd "$REPO_DIR/guest-runner"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO_BIN" build -buildvcs=false -a -o "$GUEST_RUNNER_BIN" .
)

sha256="$(sha256sum "$GUEST_RUNNER_BIN" | awk '{print $1}')"
size_bytes="$(stat -c '%s' "$GUEST_RUNNER_BIN")"
build_id="$($GO_BIN tool buildid "$GUEST_RUNNER_BIN" 2>/dev/null || true)"
built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat >"$META_JSON" <<EOF
{
  "sha256": "$sha256",
  "size_bytes": $size_bytes,
  "build_id": "$build_id",
  "built_at": "$built_at"
}
EOF

cat >"$DEBUGFS_CMDS" <<EOF
rm /usr/local/bin/guest-runner
write $GUEST_RUNNER_BIN /usr/local/bin/guest-runner
rm /etc/aegis-guest-runner.json
write $META_JSON /etc/aegis-guest-runner.json
stat /usr/local/bin/guest-runner
cat /etc/aegis-guest-runner.json
EOF

debugfs -w -f "$DEBUGFS_CMDS" "$ROOTFS_PATH"

echo "rebaked_guest_runner_sha256=$sha256"
echo "rebaked_guest_runner_build_id=$build_id"
echo "rebaked_rootfs=$ROOTFS_PATH"
