# Aegis — Task Tracker

## Done
- [x] v1: Firecracker microVM execution (Python, bash)
- [x] v1: Worker pool (5 concurrent slots), 429 on overflow
- [x] v1: API key auth, GET /health endpoint
- [x] v1: Audit log (PostgreSQL), execution state machine
- [x] v1: cgroup v2 limits (memory, CPU, pids), no-network default
- [x] v1: Deterministic teardown, startup reconciliation
- [x] v1.5: Two-drive overlayfs (read-only base + 50MB scratch per execution)
- [x] v1.5: PID 1 zombie reaping (SIGCHLD + Wait4 in guest-runner)
- [x] v2: YAML policy engine (allowed languages, resource limits, max timeout)
- [x] GitHub repo pushed and clean (4.4MB, no binaries or assets)
- [x] All 4 demo tests passing on WSL2
- [x] README written with architecture, security model, API docs

## In Progress
Nothing currently in progress.

## Up Next (in priority order)

### 1. Retry-After header (10 min)
- [ ] Add `Retry-After: 5` header to all 429 responses in handler.go
- [ ] Verify with curl that the header appears on pool overflow

### 2. GitHub Releases + install.sh (2 hours)
- [ ] Create GitHub Release v1.0 on jeshwanthsingh/Aegis
- [ ] Upload assets as release artifacts: vmlinux, alpine-base.ext4
- [ ] Update scripts/install.sh to download assets from release URL
- [ ] Test clean install on a fresh directory

### 3. aegis-cli (3 hours)
- [ ] Create cmd/aegis-cli/main.go
- [ ] Commands: `aegis run --lang python --file script.py`, `aegis run --lang bash --code "echo hello"`, `aegis health`
- [ ] Reads AEGIS_URL env var (default http://localhost:8080)
- [ ] Streams output to terminal as it arrives
- [ ] Build: `go build -o aegis ./cmd/aegis-cli`

### 4. Streaming I/O — /v1/execute/stream (1 day)
- [ ] Update guest-runner to flush stdout/stderr in real-time chunks over vsock
- [ ] Add SSE endpoint /v1/execute/stream to orchestrator
- [ ] Update aegis-cli to consume the stream

### 5. OpenClaw end-to-end test
- [ ] Verify aegis-exec skill works against live Aegis instance
- [ ] Test: agent generates code, skill calls /v1/execute, result returned to agent
- [ ] Document the integration in README

## Deferred
- vsock HTTP proxy (pip install) — complex, needs design, attempted once
- Node.js on WSL2 — needs kernel with proper entropy, deferred
- Filesystem jail — guest-side Landlock enforcement, v2.5
- GitHub IAM proxy — v3, separate tool
- Firecracker snapshots — v3, significant operational complexity

## Notes
- WSL2 timeouts: demo script uses 8000-20000ms; bare metal expected 2-3x faster
- Base image: Ubuntu 22.04 rootfs (~800MB), not Alpine despite naming
- Node.js works on bare metal, not WSL2 (entropy limitation)
- Default policy: python/bash/node allowed, 128MB RAM, 50% CPU, pids.max=100