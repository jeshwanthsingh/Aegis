#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALPINE_BRANCH="${ALPINE_BRANCH:-3.20}"
ALPINE_VERSION="${ALPINE_VERSION:-3.20.3}"
IMAGE_SIZE_MB="${IMAGE_SIZE_MB:-512}"
OUTPUT_PATH="${OUTPUT_PATH:-$REPO_DIR/build/rootfs/alpine-base.ext4}"
BACKUP_EXISTING="${BACKUP_EXISTING:-$REPO_DIR/assets/ubuntu-legacy.ext4}"
WORKDIR="${WORKDIR:-$REPO_DIR/build/rootfs/alpine-${ALPINE_VERSION}}"
GUEST_RUNNER_PATH="${GUEST_RUNNER_PATH:-$REPO_DIR/guest-runner/guest-runner}"
MNT="${MNT:-/mnt/aegis-rootfs-build}"

usage() {
  cat <<USAGE
Usage: scripts/build-alpine-rootfs.sh [options]

Options:
  --output PATH            ext4 image output path
  --backup-existing PATH   backup existing image before overwrite
  --alpine-branch VERSION  Alpine branch (default: ${ALPINE_BRANCH})
  --alpine-version VER     Alpine minirootfs version (default: ${ALPINE_VERSION})
  --size-mb N              ext4 image size in MB (default: ${IMAGE_SIZE_MB})
  --workdir PATH           working directory for downloaded artifacts
  --guest-runner PATH      guest-runner binary to bake into the image
  --no-backup              do not preserve an existing output image
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      OUTPUT_PATH="$2"
      shift 2
      ;;
    --backup-existing)
      BACKUP_EXISTING="$2"
      shift 2
      ;;
    --alpine-branch)
      ALPINE_BRANCH="$2"
      shift 2
      ;;
    --alpine-version)
      ALPINE_VERSION="$2"
      shift 2
      ;;
    --size-mb)
      IMAGE_SIZE_MB="$2"
      shift 2
      ;;
    --workdir)
      WORKDIR="$2"
      shift 2
      ;;
    --guest-runner)
      GUEST_RUNNER_PATH="$2"
      shift 2
      ;;
    --no-backup)
      BACKUP_EXISTING=""
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing prerequisite: $1" >&2
    exit 1
  }
}

need_cmd curl
need_cmd sudo
need_cmd tar
need_cmd truncate
need_cmd chroot
need_cmd mkfs.ext4

MINIROOTFS_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_BRANCH}/releases/x86_64/alpine-minirootfs-${ALPINE_VERSION}-x86_64.tar.gz"
MINIROOTFS_TARBALL="$WORKDIR/alpine-minirootfs-${ALPINE_VERSION}-x86_64.tar.gz"
PACKAGE_LOG="$WORKDIR/packages-installed.txt"
TMP_IMAGE="$OUTPUT_PATH.tmp"

mkdir -p "$(dirname "$OUTPUT_PATH")" "$WORKDIR"

if [ ! -x "$GUEST_RUNNER_PATH" ]; then
  if command -v go >/dev/null 2>&1; then
    (
      cd "$REPO_DIR/guest-runner"
      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -a -o guest-runner .
    )
  elif [ -x "$HOME/local/go/bin/go" ]; then
    (
      cd "$REPO_DIR/guest-runner"
      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$HOME/local/go/bin/go" build -buildvcs=false -a -o guest-runner .
    )
  else
    echo "guest-runner binary missing and Go toolchain unavailable" >&2
    exit 1
  fi
fi

if [ -f "$OUTPUT_PATH" ] && [ -n "$BACKUP_EXISTING" ] && [ ! -f "$BACKUP_EXISTING" ]; then
  mkdir -p "$(dirname "$BACKUP_EXISTING")"
  cp "$OUTPUT_PATH" "$BACKUP_EXISTING"
  echo "Backed up existing rootfs to $BACKUP_EXISTING"
fi

if [ ! -f "$MINIROOTFS_TARBALL" ]; then
  curl -L "$MINIROOTFS_URL" -o "$MINIROOTFS_TARBALL"
fi

cleanup() {
  if mountpoint -q "$MNT/proc"; then sudo umount "$MNT/proc"; fi
  if mountpoint -q "$MNT/sys"; then sudo umount "$MNT/sys"; fi
  if mountpoint -q "$MNT/dev"; then sudo umount "$MNT/dev"; fi
  if mountpoint -q "$MNT"; then sudo umount "$MNT"; fi
  rm -f "$TMP_IMAGE"
}
trap cleanup EXIT

rm -f "$TMP_IMAGE"
truncate -s "${IMAGE_SIZE_MB}M" "$TMP_IMAGE"
mkfs.ext4 -F "$TMP_IMAGE" >/dev/null

sudo mkdir -p "$MNT"
mountpoint -q "$MNT" && sudo umount "$MNT" || true
sudo mount "$TMP_IMAGE" "$MNT"
sudo tar -xpf "$MINIROOTFS_TARBALL" -C "$MNT"

sudo mkdir -p "$MNT/etc/apk" "$MNT/usr/local/bin" "$MNT/workspace" "$MNT/tmp" "$MNT/run" "$MNT/dev/pts"
printf 'https://dl-cdn.alpinelinux.org/alpine/v%s/main\nhttps://dl-cdn.alpinelinux.org/alpine/v%s/community\n' "$ALPINE_BRANCH" "$ALPINE_BRANCH" | sudo tee "$MNT/etc/apk/repositories" >/dev/null
sudo cp /etc/resolv.conf "$MNT/etc/resolv.conf"

sudo mount --bind /dev "$MNT/dev"
sudo mount -t proc proc "$MNT/proc"
sudo mount -t sysfs sysfs "$MNT/sys"

sudo chroot "$MNT" /bin/sh -lc 'apk update && apk add bash python3 iproute2 ca-certificates nodejs'
sudo chroot "$MNT" /bin/sh -lc 'apk info -vv' | tee "$PACKAGE_LOG" >/dev/null

sudo install -m 0755 "$GUEST_RUNNER_PATH" "$MNT/usr/local/bin/guest-runner"
if [ -x "$MNT/usr/bin/node" ]; then
  sudo ln -sf /usr/bin/node "$MNT/usr/local/bin/node"
fi

sudo rm -f "$MNT/sbin/init"
sudo tee "$MNT/sbin/init" >/dev/null <<'INITEOF'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true
mkdir -p /dev/pts /workspace
mount -t devpts devpts /dev/pts 2>/dev/null || true
exec /usr/local/bin/guest-runner
INITEOF
sudo chmod 0755 "$MNT/sbin/init"

sudo tee "$MNT/etc/aegis-rootfs-release" >/dev/null <<METAEOF
rootfs_flavor=alpine
alpine_branch=${ALPINE_BRANCH}
alpine_version=${ALPINE_VERSION}
guest_runner_path=/usr/local/bin/guest-runner
init_path=/sbin/init
packages=$(tr '\n' ' ' < "$PACKAGE_LOG")
METAEOF

sudo bash -c ': > "$MNT/etc/resolv.conf"'
touch "$WORKDIR/.built"

if mountpoint -q "$MNT/proc"; then sudo umount "$MNT/proc"; fi
if mountpoint -q "$MNT/sys"; then sudo umount "$MNT/sys"; fi
if mountpoint -q "$MNT/dev"; then sudo umount "$MNT/dev"; fi
sudo umount "$MNT"
trap - EXIT
mv "$TMP_IMAGE" "$OUTPUT_PATH"

echo "Built Alpine rootfs at $OUTPUT_PATH"
echo "Package manifest: $PACKAGE_LOG"
if [ -n "$BACKUP_EXISTING" ] && [ -f "$BACKUP_EXISTING" ]; then
  echo "Legacy backup: $BACKUP_EXISTING"
fi
