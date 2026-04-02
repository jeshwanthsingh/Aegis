#!/usr/bin/env bash
set -euo pipefail

RELEASE_URL="https://github.com/jeshwanthsingh/Aegis/releases/download/v1.0.0"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_BIN=""
DB_URL_DEFAULT="postgres://postgres:postgres@localhost/postgres?sslmode=disable"
DB_URL="${DB_URL:-$DB_URL_DEFAULT}"
ROOTFS_IMAGE_PATH="${ROOTFS_IMAGE_PATH:-$REPO_DIR/assets/alpine-base.ext4}"
ROOTFS_BUILD_MODE="${ROOTFS_BUILD_MODE:-download}"
LEGACY_ROOTFS_BACKUP="${LEGACY_ROOTFS_BACKUP:-$REPO_DIR/assets/ubuntu-legacy.ext4}"
CHECKSUM_FILE="${CHECKSUM_FILE:-$REPO_DIR/scripts/release-checksums.txt}"

find_go() {
  if command -v go >/dev/null 2>&1; then
    command -v go
  elif [ -x "$HOME/local/go/bin/go" ]; then
    printf '%s\n' "$HOME/local/go/bin/go"
  elif [ -x "/usr/local/go/bin/go" ]; then
    printf '%s\n' "/usr/local/go/bin/go"
  else
    return 1
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'Missing prerequisite: %s\n' "$2" >&2
    exit 1
  }
}

source_newer_than() {
  local target="$1"
  shift
  [ ! -f "$target" ] && return 0
  find "$@" -type f -newer "$target" -print -quit | grep -q .
}

download_if_missing() {
  local url="$1"
  local path="$2"
  local label="$3"
  if [ -f "$path" ]; then
    printf '%s already present, skipping.\n' "$label"
    return
  fi
  printf 'Downloading %s...\n' "$label"
  curl -L "$url" -o "$path"
}

safe_mount_rootfs() {
  sudo mkdir -p /mnt/rootfs
  if mountpoint -q /mnt/rootfs; then
    sudo umount /mnt/rootfs
  fi
  sudo mount "$ROOTFS_IMAGE_PATH" /mnt/rootfs
}

safe_umount_rootfs() {
  if mountpoint -q /mnt/rootfs; then
    sudo umount /mnt/rootfs
  fi
}

trap safe_umount_rootfs EXIT

echo "=== Aegis Installer ==="

[ "$(uname -s)" = "Linux" ] || { echo "Aegis install requires Linux" >&2; exit 1; }
[ -e /dev/kvm ] || { echo "Missing prerequisite: /dev/kvm" >&2; exit 1; }
need_cmd curl curl
need_cmd psql "psql (install: sudo apt install postgresql-client)"
need_cmd sudo sudo
need_cmd iptables iptables
need_cmd sha256sum sha256sum
GO_BIN="$(find_go)" || { echo "Missing prerequisite: go (install from https://go.dev/dl/)" >&2; exit 1; }

expected_checksum() {
  local artifact="$1"
  awk -v target="$artifact" '$2 == target { print $1 }' "$CHECKSUM_FILE"
}

verify_checksum() {
  local artifact="$1"
  local path="$2"
  local expected
  expected="$(expected_checksum "$artifact")"
  if [ -z "$expected" ]; then
    echo "Missing checksum entry for $artifact in $CHECKSUM_FILE" >&2
    exit 1
  fi
  local actual
  actual="$(sha256sum "$path" | awk '{print $1}')"
  if [ "$actual" != "$expected" ]; then
    echo "Checksum mismatch for $artifact" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    echo "Refusing to install unverified artifact." >&2
    exit 1
  fi
}

mkdir -p "$REPO_DIR/assets"
download_if_missing "$RELEASE_URL/vmlinux" "$REPO_DIR/assets/vmlinux" "vmlinux"
verify_checksum "vmlinux" "$REPO_DIR/assets/vmlinux"
if [ "$ROOTFS_BUILD_MODE" != "build" ] && [ "$ROOTFS_IMAGE_PATH" != "$REPO_DIR/assets/alpine-base.ext4" ] && [ ! -f "$ROOTFS_IMAGE_PATH" ]; then
  echo "Selected rootfs image not found at $ROOTFS_IMAGE_PATH" >&2
  echo "Build it with: ./scripts/build-alpine-rootfs.sh --output $ROOTFS_IMAGE_PATH" >&2
  exit 1
fi

if ! command -v firecracker >/dev/null 2>&1; then
  echo "Downloading firecracker..."
  curl -L "$RELEASE_URL/firecracker" -o /tmp/firecracker
  verify_checksum "firecracker" /tmp/firecracker
  sudo install -m 0755 /tmp/firecracker /usr/local/bin/firecracker
else
  echo "firecracker already on PATH, skipping."
fi

cd "$REPO_DIR"
if source_newer_than /tmp/aegis-bin cmd internal go.mod go.sum; then
  echo "Building orchestrator..."
  "$GO_BIN" build -buildvcs=false -o /tmp/aegis-bin ./cmd/orchestrator
else
  echo "orchestrator already up to date, skipping build."
fi

if source_newer_than /usr/local/bin/aegis cmd go.mod go.sum; then
  echo "Building aegis-cli..."
  "$GO_BIN" build -buildvcs=false -o /tmp/aegis-cli ./cmd/aegis-cli
  sudo install -m 0755 /tmp/aegis-cli /usr/local/bin/aegis
else
  echo "aegis-cli already up to date, skipping build."
fi

if source_newer_than "$REPO_DIR/guest-runner/guest-runner" "$REPO_DIR/guest-runner" "$REPO_DIR/go.mod" "$REPO_DIR/go.sum"; then
  echo "Building guest-runner..."
  (
    cd "$REPO_DIR/guest-runner"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO_BIN" build -buildvcs=false -a -o guest-runner .
  )
else
  echo "guest-runner already up to date, skipping build."
fi

mkdir -p "$(dirname "$ROOTFS_IMAGE_PATH")"
if [ "$ROOTFS_BUILD_MODE" = "build" ]; then
  echo "Building Alpine rootfs..."
  "$REPO_DIR/scripts/build-alpine-rootfs.sh" --output "$ROOTFS_IMAGE_PATH" --backup-existing "$LEGACY_ROOTFS_BACKUP" --guest-runner "$REPO_DIR/guest-runner/guest-runner"
else
  download_if_missing "$RELEASE_URL/alpine-base.ext4" "$ROOTFS_IMAGE_PATH" "alpine-base.ext4"
  verify_checksum "alpine-base.ext4" "$ROOTFS_IMAGE_PATH"
fi


echo "Baking guest-runner into rootfs..."
safe_mount_rootfs
sudo install -m 0755 "$REPO_DIR/guest-runner/guest-runner" /mnt/rootfs/usr/local/bin/guest-runner
safe_umount_rootfs

if [ -z "${PGPASSWORD:-}" ]; then
  read -rsp "Enter PostgreSQL password for user 'postgres' (leave blank to use local auth/.pgpass): " PGPASSWORD_INPUT
  echo ""
  if [ -n "$PGPASSWORD_INPUT" ]; then
    export PGPASSWORD="$PGPASSWORD_INPUT"
  fi
fi

echo "Setting up database..."
if ! psql "$DB_URL" -tAc "SELECT 1 FROM pg_database WHERE datname='aegis'" | grep -q 1; then
  psql "$DB_URL" -c "CREATE DATABASE aegis;"
else
  echo "Database aegis already exists, skipping create."
fi

A_DB_URL="${DB_URL%/postgres*}/aegis?sslmode=disable"
psql "$A_DB_URL" -f db/schema.sql >/dev/null
echo "Schema applied."

echo ""
echo "=== Aegis installed successfully ==="
echo ""
echo "Run preflight with:"
echo "  ./scripts/preflight.sh"
echo ""
echo "Run local smoke with:"
echo "  ./scripts/smoke-local.sh"
echo ""
echo "Build a real Alpine/musl guest image with:"
echo "  ./scripts/build-alpine-rootfs.sh"
echo ""
echo "Run with:"
echo "  sudo env PATH=\$PATH /tmp/aegis-bin --db '$A_DB_URL' --assets-dir '$REPO_DIR/assets' [--rootfs-path /path/to/rootfs.ext4]"
