# HANDOFF.md

## Status
**Active investigation: Node.js entropy starvation in Firecracker guest**

## What works
- Python execution: ✅ full VM boot → vsock → result in ~3.5s
- Bash execution: ✅ same path
- Worker pool (5 slots): ✅ 5 concurrent VMs, all cleaned up
- API key auth (Bearer token): ✅ 401 on missing/wrong key
- GET /health endpoint: ✅ returns slots_available/total
- HTTP 413 on body > 128KB: ✅
- Teardown: ✅ scratch image, sockets, cgroup all removed
- Postgres audit log: ✅ status column, reconcile on startup
- 4/4 demo tests (Python/bash/concurrent): ✅ scripts/run-demo.sh
- Node.js binary: installed at /usr/local/bin/node (v20) in rootfs
- guest-runner: rebuilt with sendError helper, absolute paths, StdoutPipe

## Active blocker: Node.js hangs on getrandom()
**Root cause confirmed:** entropy_avail = 16–18 inside the booted guest.
Node.js v20 calls `getrandom()` during V8/OpenSSL init which blocks until entropy ≥ 256.
Python and bash don't call getrandom() at startup — that's why they work.

**What has been tried:**
- `random.trust_cpu=on` boot arg → no effect (CPU RDRAND not exposed to guest kernel)
- `PUT /entropy` (virtio-rng Firecracker API) → Firecracker accepts it but `/dev/hwrng` is missing in guest → the quickstart vmlinux does NOT have CONFIG_HW_RANDOM_VIRTIO
- rng-tools in chroot → never ran as a booted service, entropy unchanged

**Next step: haveged**
Install haveged in rootfs, enable as systemd service, order guest-runner After=haveged.service.
This is a pure-software entropy daemon that works without hardware RNG.

```bash
sudo mount ~/aegis/assets/alpine-base.ext4 /mnt/rootfs
sudo chroot /mnt/rootfs apt-get install -y haveged
sudo chroot /mnt/rootfs systemctl enable haveged
sudo tee /mnt/rootfs/etc/systemd/system/guest-runner.service << 'EOF'
[Unit]
Description=Aegis Guest Runner
After=haveged.service
Requires=haveged.service

[Service]
Type=simple
ExecStart=/usr/local/bin/guest-runner
Restart=no
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
sudo umount /mnt/rootfs
```

Then verify in order:
1. `entropy_avail` → must be 256+
2. `python3 -c 'import os; print(os.getrandom(8))'` → must not block
3. `node --version`
4. `node -e "console.log('hello from node')"`

## Key file locations
| File | Purpose |
|------|---------|
| `internal/executor/firecracker.go` | VM boot sequence, PUT /entropy already added |
| `internal/executor/vsock.go` | SendPayload takes deadline (not hardcoded 10s) |
| `internal/executor/pool.go` | 5-slot counting semaphore |
| `internal/executor/lifecycle.go` | cgroup v2 setup + teardown |
| `internal/api/handler.go` | WithAuth, HandleHealth, NewHandler, 128KB body limit |
| `cmd/orchestrator/main.go` | reads AEGIS_API_KEY, wires pool + auth + health |
| `guest-runner/main.go` | sendError helper, resolveInterpreter, StdoutPipe |
| `scripts/run-demo.sh` | 4 tests: fork bomb, exfiltration, escape, concurrency |
| `scripts/install.sh` | full install on fresh Ubuntu 22.04/24.04 |
| `scripts/build-rootfs.sh` | mounts rootfs, writes start-runner.sh wrapper |
| `db/schema.sql` | executions table + status column |

## Current boot_args
`console=ttyS0 reboot=k panic=1 pci=off`
(random.trust_cpu=on was removed — proven not to work with this vmlinux)

## Current PUT /entropy state
Added to NewVM() sequence in firecracker.go — Firecracker accepts it but guest kernel lacks
CONFIG_HW_RANDOM_VIRTIO so /dev/hwrng never appears.

## Run commands
```bash
# Build orchestrator
cd ~/aegis && ~/local/go/bin/go build -o /tmp/aegis-bin ./cmd/orchestrator/

# Build guest-runner
cd ~/aegis/guest-runner && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 ~/local/go/bin/go build -a -o guest-runner .

# Start orchestrator
sudo env "PATH=$PATH" /tmp/aegis-bin --db 'postgres://postgres:postgres@localhost/aegis?sslmode=disable'

# Bake guest-runner into rootfs
sudo mount ~/aegis/assets/alpine-base.ext4 /mnt/rootfs
sudo cp ~/aegis/guest-runner/guest-runner /mnt/rootfs/usr/local/bin/guest-runner
sudo umount /mnt/rootfs

# Run demo (4 tests)
bash scripts/run-demo.sh
```

## Known issues
- Node.js lang=node times out (entropy starvation, fix in progress)
- PUT /entropy in firecracker.go is a no-op for this vmlinux (kept in code, harmless)
- guest-runner nodeEnvDiag() adds diagnostic output to stderr for lang=node (remove after fix confirmed)
- install.sh not tested end-to-end yet
