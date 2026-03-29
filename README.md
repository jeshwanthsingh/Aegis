[![CI](https://github.com/jeshwanthsingh/Aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/jeshwanthsingh/Aegis/actions/workflows/ci.yml)
# Aegis

A self-hostable Firecracker-backed execution plane for OpenClaw that isolates untrusted AI-generated code in hardware-isolated microVMs.

## Install

```bash
curl -sSL https://raw.githubusercontent.com/jeshwanthsingh/Aegis/main/scripts/install.sh | sudo bash
```

## Why It Exists

OpenClaw can write and run code on demand, which means a bad prompt, bad tool call, or bad generated script can execute with ambient trust on the host machine. Cisco's public work on agentic AI security makes the same gap clear: prompt and policy controls do not solve the code-execution boundary problem by themselves. Aegis exists to close that gap by forcing execution into disposable Firecracker microVMs with hard resource limits, no network interfaces, and deterministic teardown.

## Architecture

```text
OpenClaw
   |
   | POST /v1/execute { lang, code, timeout_ms, profile?, workspace_id? }
   v
Aegis control plane (Go HTTP API)
   |
   | boot VM + apply cgroup limits + dial vsock
   v
Firecracker microVM
   |
   | virtio-vsock
   v
Guest runner (Go binary inside guest)
   |
   | exec python3 or bash
   v
Result { stdout, stderr, exit_code, duration_ms }
```

## Security Model

What Aegis protects:
- The code execution lane. Generated code runs in a separate VM, not on the host.
- The host filesystem and process table from guest reads and writes.
- The host from fork bombs and runaway processes via `pids.max`, CPU, memory, and timeout enforcement.
- The network boundary by booting the VM with no NIC attached.

Non-goals:
- It does not stop prompt injection at the LLM layer.
- It does not secure agent integrations such as Slack, email, GitHub, or cloud APIs.
- It does not manage credentials outside the execution path.
- It does not replace OpenClaw policy controls or NeMo Guardrails.

## Demo Results

Current passing WSL2 demo on the restored kernel:

1. Fork bomb

```text
PASS - fork bomb contained in 8002ms
```

Proves: the guest can be forced into failure without exhausting host PID space.

2. Network exfiltration

```text
PASS - outbound connection blocked in 10004ms
```

Proves: with no network interface attached, guest code cannot reach the internet.

3. Host filesystem escape

```text
PASS - guest /etc/passwd returned in 5193ms; VM file had 22 lines vs host 29 lines
```

Proves: the guest sees its own root filesystem, not the host filesystem.

4. Worker pool concurrency

```text
PASS - 5/5 concurrent workers, /tmp/aegis/ clean
```

Proves: the worker pool, teardown path, and scratch cleanup all hold under concurrent load on WSL2.

## Benchmarks

- Python p50: ~2-3s bare metal, ~3-6s WSL2
- Bash p50: ~2s bare metal, ~2-3s WSL2

WSL2, cold boot, full-copy clone. Bare metal expected 2-3x faster.

## Supported Languages

- Python: supported.
- Bash: supported.
- Node.js: works on bare metal Linux, not on WSL2 in the current setup due to guest entropy/runtime limitations.

## API

### `POST /v1/execute`

Request body:

```json
{
  "lang": "python",
  "code": "print(1)",
  "timeout_ms": 5000
}
```

Supported `lang` values:
- `python`
- `bash`
- `node`

Optional request fields:
- `profile`: select a compute profile such as `nano`, `standard`, or `crunch`
- `workspace_id`: attach a persistent ext4-backed workspace mounted at `/workspace`

Response body:

```json
{
  "stdout": "1\n",
  "stderr": "",
  "exit_code": 0,
  "duration_ms": 6223,
  "execution_id": "023ebc28-dca0-4241-a5ae-ff4ed4f51505"
}
```

Timeout and sandbox failures return an `error` field instead of normal process output.

### `DELETE /v1/workspaces/{id}`

Deletes a persistent workspace image from the host.

Response body:

```json
{
  "status": "deleted",
  "workspace_id": "agent-alpha-123"
}
```

### `GET /health`

Response body:

```json
{
  "status": "ok",
  "worker_slots_available": 5,
  "worker_slots_total": 5
}
```

### CLI

```bash
aegis health
aegis run --lang python --code "print('hello')"
aegis run --lang bash --file script.sh
aegis run --lang python --code "..." --stream
```

## Install Details

Primary install path:

```bash
bash scripts/install.sh
```

Prerequisites:
- Linux host with KVM available at `/dev/kvm`
- Go 1.22+
- Firecracker v1.7.0 on `PATH`
- PostgreSQL
- Guest assets present in `assets/`

Manual build:

```bash
cd ~/aegis
go build -o /tmp/aegis-bin ./cmd/orchestrator
cd ~/aegis/guest-runner
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o guest-runner .
```

Database:

```bash
psql -d aegis -f db/schema.sql
```

Run:

```bash
sudo env "PATH=$PATH" /tmp/aegis-bin --db 'postgres://postgres:<your-password>@localhost/aegis?sslmode=disable'
```

Example request:

```bash
curl -s -X POST http://localhost:8080/v1/execute \
  -H "Content-Type: application/json" \
  -d '{"lang":"python","code":"print(1)","timeout_ms":8000}' | jq .
```

## OpenClaw Integration

Aegis ships a skill that lets your OpenClaw agent run code in isolated Firecracker microVMs instead of locally.

### Quick setup

1. Start Aegis orchestrator
2. Install the skill:
```bash
mkdir -p ~/.openclaw/workspace/skills/aegis-exec
curl -L https://raw.githubusercontent.com/jeshwanthsingh/Aegis/main/openclaw-plugin/SKILL.md \
  -o ~/.openclaw/workspace/skills/aegis-exec/SKILL.md
```
3. Restart your OpenClaw gateway
4. Ask your agent: `Use the Aegis sandbox to run this Python code: print('hello')`

See `docs/openclaw-integration.md` for full setup and troubleshooting.

## Roadmap

- v1 — shipped: Python + bash execution, worker pool, API key auth, audit log, cgroup v2 limits
- v1.5 — shipped: two-drive overlayfs fast boot, PID 1 zombie reaping
- v2 — shipped: YAML policy engine, streaming I/O (SSE), aegis-cli
- v2.1 — shipped: compute profiles
- v2.2 — shipped: persistent workspaces (`workspace_id`, `/workspace`, delete API)
- v3 — planned: vsock HTTP proxy (pip install support)
- v4 — planned: GitHub IAM proxy for credential isolation
