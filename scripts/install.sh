#!/usr/bin/env bash
set -euo pipefail

RELEASE_URL="https://github.com/jeshwanthsingh/Aegis/releases/download/v1.0.0"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== Aegis Installer ==="

# 1. Check prerequisites
missing=()

if [ ! -e /dev/kvm ]; then
    missing+=("/dev/kvm")
fi

if ! command -v go &>/dev/null; then
    missing+=("go")
fi

if ! command -v psql &>/dev/null; then
    missing+=("psql")
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
go build -buildvcs=false -o /tmp/aegis-bin ./cmd/orchestrator

# 4. Build guest-runner and bake into rootfs
echo "Building guest-runner..."
cd "$REPO_DIR/guest-runner"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o guest-runner .
sudo mount "$REPO_DIR/assets/alpine-base.ext4" /mnt/rootfs
sudo cp guest-runner /mnt/rootfs/usr/local/bin/guest-runner
sudo umount /mnt/rootfs

# 5. Set up database
echo "Setting up database..."
cd "$REPO_DIR"
psql -h localhost -U postgres -c "CREATE DATABASE aegis;" 2>/dev/null || echo "Database already exists."
psql -h localhost -U postgres -d aegis -f db/schema.sql

# 6. Done
echo ""
echo "=== Aegis installed successfully ==="
echo ""
echo "Run with:"
echo "  sudo env PATH=\$PATH /tmp/aegis-bin --db 'postgres://postgres:postgres@localhost/aegis?sslmode=disable'"
echo ""
echo "Test with:"
echo "  curl -s -X POST http://localhost:8080/v1/execute \\" 
echo "    -H 'Content-Type: application/json' \\" 
echo "    -d '{\"lang\":\"python\",\"code\":\"print(1)\",\"timeout_ms\":10000}' | jq ."