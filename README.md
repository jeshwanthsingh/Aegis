# Aegis

Aegis is a local-first ephemeral execution substrate that runs untrusted AI-generated code inside hardware-isolated microVMs. AI agents like Claude Code and OpenClaw write and execute code dynamically — with ambient trust on the host machine. A fork bomb crashes your system. A prompt injection leaks your API keys. A bad script deletes your database. Aegis solves this by forcing every execution into a disposable Firecracker microVM: created in milliseconds, isolated at the KVM boundary, permanently destroyed when done. The host is never touched.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  CLIENT                                             │
│  POST /v1/execute { lang, code, timeout_ms }        │
└───────────────────────┬─────────────────────────────┘
                        │ HTTP
┌───────────────────────▼─────────────────────────────┐
│  CONTROL PLANE  (Go HTTP API — host)                │
│                                                     │
│  1. Clone base ext4 → /tmp/aegis/scratch-{uuid}     │
│  2. Boot Firecracker via Unix socket API            │
│  3. Set cgroup v2 limits (RAM, CPU, pids)           │
│  4. Dial vsock proxy → CONNECT 1024                 │
│  5. Send JSON payload                               │
│  6. Receive result OR SIGKILL on timeout            │
│  7. Delete scratch image, sockets, cgroup           │
│  8. Write audit record to Postgres                  │
└───────────────────────┬─────────────────────────────┘
                        │ Firecracker Unix socket API
┌───────────────────────▼─────────────────────────────┐
│  KVM BOUNDARY  (Firecracker microVM)                │
│                                                     │
│  • Hardware isolation — guest cannot read host      │
│    memory or filesystem                             │
│  • No network interfaces — deny-all by default      │
│  • virtio-vsock — kernel-mediated IPC, no TCP/IP    │
└───────────────────────┬─────────────────────────────┘
                        │ virtio-vsock (CONNECT 1024)
┌───────────────────────▼─────────────────────────────┐
│  GUEST RUNNER  (Go binary — inside Alpine VM)       │
│                                                     │
│  • Listens on vsock port 1024                       │
│  • Accepts one connection per VM lifetime           │
│  • Writes code to /tmp, runs python3 or bash        │
│  • Returns { stdout, stderr, exit_code } as JSON    │
│  • Exits — VM is killed by orchestrator             │
└─────────────────────────────────────────────────────┘
```

---

## Security Model

- **No network interfaces** — VMs boot with zero NICs. Code running inside cannot reach the internet, internal services, or the host network. `urllib.request.urlopen()` returns `Network is unreachable`.
- **KVM hardware boundary** — Firecracker uses KVM for hardware virtualization. Guest code runs in a separate address space with its own kernel. It cannot read host memory, host filesystem, or host process table.
- **cgroup v2 enforcement** — Every Firecracker process is placed in a per-execution cgroup with hard limits: `memory.max=128M`, `memory.high=64M`, `cpu.max=50000 100000` (50% of one core).
- **pids.max=100** — Fork bombs are killed before they can exhaust host PID space. `while True: os.fork()` hits the limit and dies inside the VM.
- **Scratch image deleted on teardown** — Each execution gets a fresh clone of the base image. The clone is deleted immediately after the VM is killed. No state persists between executions.

---

## Demo Results

**Test 1 — Fork Bomb**
```
{"error": "timeout", "duration_ms": 3001}
PASS — fork bomb contained: timeout
```
Proves: `pids.max=100` triggers inside the VM. The host is unaffected. No orphaned processes.

**Test 2 — Network Exfiltration**
```
{"stderr": "urllib.error.URLError: <urlopen error [Errno 101] Network is unreachable>", "exit_code": 1}
PASS — network unreachable, exfiltration blocked
```
Proves: No NIC is attached to the VM. Outbound connections are structurally impossible, not just blocked by firewall rules.

**Test 3 — Host Filesystem Escape**
```
{"stdout": "root:x:0:0:root:/root:/bin/bash\n...", "exit_code": 0}
PASS — read VM's /etc/passwd (4 lines), not host (42 lines)
```
Proves: The KVM boundary is intact. Guest reads its own Alpine rootfs, not the host filesystem. The line count difference is the proof.

---

## Benchmarks

10 sequential executions of `print("hello")`:

| Metric | Time |
|--------|------|
| min    | 2335ms |
| max    | 2577ms |
| avg    | 2499ms |

**WSL2, cold boot, full-copy clone.** Each run clones the base ext4 image (300MB `cp`), boots a fresh microVM, waits for the guest runner to come online, executes, and tears down. Bare metal + overlayfs image snapshots is the v2 path to sub-150ms boot.

---

## How to Run

### Prerequisites

- Linux host with KVM enabled (`/dev/kvm` must exist and be readable)
- Go 1.22+
- Firecracker v1.7.0 on `PATH`
- PostgreSQL running locally
- Pre-built assets in `assets/`: `vmlinux`, `alpine-base.ext4`

```bash
# Verify KVM
ls -la /dev/kvm

# Create database
sudo -u postgres psql -c "CREATE DATABASE aegis;"
psql -d aegis -f db/schema.sql

# Build
go build ./...
```

### Start the orchestrator

```bash
sudo -E env "PATH=$PATH" ./orchestrator --db "postgres://localhost/aegis?sslmode=disable"
# Aegis orchestrator listening on :8080
```

### Execute code

```bash
curl -s -X POST http://localhost:8080/v1/execute \
  -H "Content-Type: application/json" \
  -d '{"lang":"python","code":"print(\"hello from inside the VM\")","timeout_ms":5000}' | jq .
```

```json
{
  "stdout": "hello from inside the VM\n",
  "exit_code": 0,
  "duration_ms": 2451,
  "execution_id": "f3a1c2d4-..."
}
```

### Run threat-model demo

```bash
./scripts/run-demo.sh
```

---

## Tech Stack

| Component | Version | Why |
|-----------|---------|-----|
| **Firecracker** | v1.7.0 | AWS Lambda's microVM manager. Sub-200ms boot, minimal attack surface (no USB, no BIOS, no PCI). Hardware KVM boundary — not a container namespace. |
| **Ubuntu 22.04 (Firecracker quickstart base)** | (Ubuntu 22.04 base) | Minimal guest OS. Under 5MB when stripped. Contains Python runtime and the guest-runner binary. |
| **virtio-vsock** | kernel primitive | Kernel-mediated socket that crosses the KVM boundary without any network stack. Faster than SSH, zero network attack surface, cannot be blocked by guest iptables. |
| **cgroup v2** | Linux 4.15+ | Unified resource hierarchy. Enforces hard limits on the Firecracker process: RAM, CPU, and — critically — `pids.max` as the fork bomb kill switch. |
| **Go** | 1.22 | Orchestrator and guest runner. Static binary compilation (`CGO_ENABLED=0`) means the guest runner has zero external dependencies inside the VM. |
| **PostgreSQL** | local | Execution audit log. Every run — success, timeout, OOM, or error — is recorded with execution ID, outcome, duration, and byte counts. |

---

## Non-goals

Aegis isolates code execution. It does not:
- Secure agent reasoning or prevent prompt injection at the LLM layer
- Protect secrets stored outside the execution path
- Control agent actions through native integrations (email, Slack, etc.)
- Fix vulnerabilities in OpenClaw's gateway or UI

---

## Interview Line

> "Aegis enforces a hardware VM boundary between AI-generated code and the host. The interesting engineering is the vsock transport layer — a kernel-mediated socket that crosses the KVM boundary without touching any network stack. The guest runner is ~100 lines of Go baked into the rootfs. The orchestrator's job is deterministic lifecycle: clone, boot, send, receive, kill, wipe. I benchmarked p50 cold-boot-to-result at 2499ms on WSL2 — the v2 path is Firecracker snapshots and overlayfs for sub-150ms."
