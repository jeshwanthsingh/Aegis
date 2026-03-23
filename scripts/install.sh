#!/usr/bin/env bash
set -euo pipefail

RELEASE_URL="https://github.com/jeshwanthsingh/Aegis/releases/download/v1.0.0"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== Aegis Installer ==="

# 1. Check prerequisites
missing=()
GO_BIN=""

if [ ! -e /dev/kvm ]; then
    missing+=("/dev/kvm")
fi

# Check for go in common locations, not just PATH
if command -v go &>/dev/null; then
    GO_BIN=$(command -v go)
elif [ -x "$HOME/local/go/bin/go" ]; then
    GO_BIN="$HOME/local/go/bin/go"
elif [ -x "/usr/local/go/bin/go" ]; then
    GO_BIN="/usr/local/go/bin/go"
elif [ -x "/home/$(logname)/local/go/bin/go" ]; then
    GO_BIN="/home/$(logname)/local/go/bin/go"
fi

if [ -z "$GO_BIN" ]; then
    missing+=("go (install from https://go.dev/dl/)")
fi

if ! command -v psql &>/dev/null; then
    missing+=("psql (install: sudo apt install postgresql)")
fi

if ! command -v curl &>/dev/null; then
    missing+=("curl")
fi

if [ ${#missing[@]} -gt 0 ]; then
    echo "Missing prerequisites: ${missing[*]}"
    exit 1
fi

# 2. Download assets (skip if already present)
mkdir -p "$REPO_DIR/assets"

if [ ! -f "$REPO_DIR/assets/vmlinux" ]; then
    echo "Downloading vmlinux (20MB)..."
    curl -L "$RELEASE_URL/vmlinux" -o "$REPO_DIR/assets/vmlinux"
else
    echo "vmlinux already present, skipping."
fi

if [ ! -f "$REPO_DIR/assets/alpine-base.ext4" ]; then
    echo "Downloading alpine-base.ext4 (812MB, this will take a while)..."
    curl -L "$RELEASE_URL/alpine-base.ext4" -o "$REPO_DIR/assets/alpine-base.ext4"
else
    echo "alpine-base.ext4 already present, skipping."
fi

if ! command -v firecracker &>/dev/null; then
    echo "Downloading firecracker..."
    curl -L "$RELEASE_URL/firecracker" -o /tmp/firecracker
    sudo mv /tmp/firecracker /usr/local/bin/firecracker
    sudo chmod +x /usr/local/bin/firecracker
else
    echo "firecracker already on PATH, skipping."
fi

# 3. Build orchestrator
echo "Building orchestrator..."
cd "$REPO_DIR"
"$GO_BIN" build -buildvcs=false -o /tmp/aegis-bin ./cmd/orchestrator

# 4. Build aegis-cli
echo "Building aegis-cli..."
cd "$REPO_DIR"
"$GO_BIN" build -buildvcs=false -o /usr/local/bin/aegis ./cmd/aegis-cli
echo "aegis-cli installed to /usr/local/bin/aegis"

# 5. Build guest-runner and bake into rootfs
echo "Building guest-runner..."
cd "$REPO_DIR/guest-runner"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO_BIN" build -buildvcs=false -a -o guest-runner .
sudo mkdir -p /mnt/rootfs
sudo mount "$REPO_DIR/assets/alpine-base.ext4" /mnt/rootfs
sudo cp guest-runner /mnt/rootfs/usr/local/bin/guest-runner
sudo umount /mnt/rootfs

# 6. Set up database
echo "Setting up database..."
cd "$REPO_DIR"

# Get postgres password
read -rsp "Enter PostgreSQL password for user 'postgres': " PG_PASS
echo ""

export PGPASSWORD="$PG_PASS"

psql -h localhost -U postgres -c "CREATE DATABASE aegis;" 2>/dev/null || echo "Database already exists."
psql -h localhost -U postgres -d aegis -f db/schema.sql

unset PGPASSWORD

echo ""
echo "=== Aegis installed successfully ==="
echo ""
echo "Run with:"
echo "  sudo env PATH=\$PATH /tmp/aegis-bin --db 'postgres://postgres:$PG_PASS@localhost/aegis?sslmode=disable'"
echo ""
echo "Test with:"
echo "  aegis health"
echo "  aegis run --lang python --code \"print('hello')\""