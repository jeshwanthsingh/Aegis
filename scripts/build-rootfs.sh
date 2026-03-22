#!/bin/bash
set -euo pipefail

ROOTFS="$HOME/aegis/assets/alpine-base.ext4"
MNT="/mnt/rootfs"

sudo mkdir -p "$MNT"
sudo mount "$ROOTFS" "$MNT"

# Create startup wrapper that mounts essential filesystems before guest-runner.
# Node.js requires /proc and /dev at startup; Python works without them.
sudo tee "$MNT/usr/local/bin/start-runner.sh" << 'EOF'
#!/bin/bash
mount -t proc proc /proc 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
exec /usr/local/bin/guest-runner
EOF
sudo chmod +x "$MNT/usr/local/bin/start-runner.sh"

# Update systemd service to invoke wrapper instead of guest-runner directly
sudo tee "$MNT/etc/systemd/system/guest-runner.service" << 'EOF'
[Unit]
Description=Aegis Guest Runner
After=sysinit.target
DefaultDependencies=no

[Service]
Type=simple
ExecStart=/usr/local/bin/start-runner.sh
Restart=no

[Install]
WantedBy=multi-user.target
EOF

echo "--- start-runner.sh ---"
cat "$MNT/usr/local/bin/start-runner.sh"
echo "--- guest-runner.service ---"
cat "$MNT/etc/systemd/system/guest-runner.service"

sudo umount "$MNT"
echo "Done"
