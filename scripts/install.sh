#!/usr/bin/env bash
# install.sh — install Aegis on a fresh Ubuntu 22.04/24.04 machine.
# Must be run as root.
set -euo pipefail

FIRECRACKER_VERSION="1.7.0"
GO_VERSION="1.22.5"
INSTALL_DIR="/opt/aegis"
BIN="/usr/local/bin/aegis-server"
CONFIG_DIR="/etc/aegis"
CONFIG_FILE="$CONFIG_DIR/config.env"
VMLINUX_URL="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin"
ROOTFS_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.7/x86_64/ubuntu-22.04.ext4"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[aegis]${NC} $*"; }
warn()  { echo -e "${YELLOW}[aegis]${NC} $*"; }
die()   { echo -e "${RED}[aegis] ERROR:${NC} $*" >&2; exit 1; }

# ── 1. Root check ──────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "This script must be run as root. Try: sudo bash install.sh"

# ── 2. Preflight checks ────────────────────────────────────────────────────────
info "Running preflight checks..."

[[ -e /dev/kvm ]] || die "/dev/kvm not found. KVM must be available (bare metal or nested virt enabled)."
command -v curl &>/dev/null || die "curl is required but not installed. Run: apt install -y curl"
command -v jq &>/dev/null  || { warn "jq not found — installing..."; apt-get install -y -qq jq; }

info "Preflight passed."

# ── 3. Install Firecracker ─────────────────────────────────────────────────────
if ! command -v firecracker &>/dev/null || \
   ! firecracker --version 2>&1 | grep -q "$FIRECRACKER_VERSION"; then
    info "Installing Firecracker v${FIRECRACKER_VERSION}..."
    ARCH=$(uname -m)
    FC_URL="https://github.com/firecracker-microvm/firecracker/releases/download/v${FIRECRACKER_VERSION}/firecracker-v${FIRECRACKER_VERSION}-${ARCH}.tgz"
    TMP=$(mktemp -d)
    curl -fsSL "$FC_URL" | tar -xz -C "$TMP"
    install -m 755 "$TMP/release-v${FIRECRACKER_VERSION}-${ARCH}/firecracker-v${FIRECRACKER_VERSION}-${ARCH}" \
        /usr/local/bin/firecracker
    rm -rf "$TMP"
    info "Firecracker $(firecracker --version 2>&1 | head -1) installed."
else
    info "Firecracker v${FIRECRACKER_VERSION} already present."
fi

# ── 4. Install Go ──────────────────────────────────────────────────────────────
install_go() {
    info "Installing Go ${GO_VERSION}..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GOARCH="amd64" ;;
        aarch64) GOARCH="arm64" ;;
        *) die "Unsupported architecture: $ARCH" ;;
    esac
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" | \
        tar -xz -C /usr/local
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
    info "Go $(go version) installed."
}

if command -v go &>/dev/null; then
    GOVER=$(go version | awk '{print $3}' | sed 's/go//')
    MAJOR=$(echo "$GOVER" | cut -d. -f1)
    MINOR=$(echo "$GOVER" | cut -d. -f2)
    if [[ "$MAJOR" -lt 1 ]] || [[ "$MAJOR" -eq 1 && "$MINOR" -lt 22 ]]; then
        warn "Go $GOVER is older than 1.22 — upgrading..."
        install_go
    else
        info "Go $GOVER already present."
    fi
else
    install_go
fi

# ── 5. Install PostgreSQL ──────────────────────────────────────────────────────
if ! command -v psql &>/dev/null; then
    info "Installing PostgreSQL..."
    apt-get install -y -qq postgresql
fi

if ! service postgresql status &>/dev/null; then
    info "Starting PostgreSQL..."
    service postgresql start
    sleep 2
fi
info "PostgreSQL running."

# ── 6. Copy project source ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
info "Copying project source to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
rsync -a --exclude='.git' --exclude='assets' "$REPO_ROOT/" "$INSTALL_DIR/"

# ── 7. Download assets ─────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR/assets"

if [[ ! -f "$INSTALL_DIR/assets/vmlinux" ]]; then
    info "Downloading vmlinux kernel..."
    curl -fsSL -o "$INSTALL_DIR/assets/vmlinux" "$VMLINUX_URL"
    info "vmlinux downloaded ($(du -h "$INSTALL_DIR/assets/vmlinux" | cut -f1))."
else
    info "vmlinux already present."
fi

if [[ ! -f "$INSTALL_DIR/assets/alpine-base.ext4" ]]; then
    info "Downloading base rootfs (Ubuntu 22.04, ~300MB)..."
    curl -fsSL -o "$INSTALL_DIR/assets/alpine-base.ext4" "$ROOTFS_URL"
    info "Rootfs downloaded ($(du -h "$INSTALL_DIR/assets/alpine-base.ext4" | cut -f1))."
else
    info "Base rootfs already present."
fi

# ── 8. Build binary ────────────────────────────────────────────────────────────
info "Building aegis-server..."
cd "$INSTALL_DIR"
go build -o "$BIN" ./cmd/orchestrator/
info "Binary built: $BIN"

# ── 9. Setup database ──────────────────────────────────────────────────────────
info "Setting up Aegis database..."
if ! sudo -u postgres psql -lqt 2>/dev/null | cut -d'|' -f1 | grep -qw aegis; then
    sudo -u postgres createdb aegis
    info "Created database 'aegis'."
else
    info "Database 'aegis' already exists."
fi
sudo -u postgres psql -d aegis -f "$INSTALL_DIR/db/schema.sql" -q
info "Schema applied."

# ── 10. Generate API key ───────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_FILE" ]]; then
    API_KEY=$(openssl rand -hex 16)
    cat > "$CONFIG_FILE" << EOF
AEGIS_API_KEY=${API_KEY}
EOF
    chmod 600 "$CONFIG_FILE"
    info "API key generated and saved to $CONFIG_FILE."
else
    API_KEY=$(grep AEGIS_API_KEY "$CONFIG_FILE" | cut -d= -f2)
    info "Using existing API key from $CONFIG_FILE."
fi

# ── 11. Systemd service ────────────────────────────────────────────────────────
cat > /etc/systemd/system/aegis.service << 'UNIT'
[Unit]
Description=Aegis Execution Plane
After=network.target postgresql.service

[Service]
Type=simple
EnvironmentFile=/etc/aegis/config.env
ExecStart=/usr/local/bin/aegis-server --db postgres://postgres@localhost/aegis?sslmode=disable
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable aegis.service
info "Systemd service installed and enabled."

# ── 12. Success ────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Aegis installed successfully               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Start:    systemctl start aegis"
echo "  Status:   systemctl status aegis"
echo "  Logs:     journalctl -u aegis -f"
echo ""
echo "  API key:  $API_KEY"
echo ""
echo "  Test:"
echo "    curl -s http://localhost:8080/v1/execute \\"
echo "      -H 'Authorization: Bearer $API_KEY' \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"lang\":\"python\",\"code\":\"print(42)\"}'"
echo ""
