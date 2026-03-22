# Aegis

A self-hostable Firecracker-backed execution plane for OpenClaw that isolates untrusted AI-generated code in hardware-isolated microVMs.

## Install

```bash
curl -sSL https://raw.githubusercontent.com/YOUR_REPO/aegis/main/scripts/install.sh | sudo bash
```

## Why It Exists

OpenClaw can write and run code on demand, which means a bad prompt, bad tool call, or bad generated script can execute with ambient trust on the host machine. Cisco's public work on agentic AI security makes the same gap clear: prompt and policy controls do not solve the code-execution boundary problem by themselves. Aegis exists to close that gap by forcing execution into disposable Firecracker microVMs with hard resource limits, no network interfaces, and deterministic teardown.

## Architecture

```text
OpenClaw
   |
   | POST /v1/execute { lang, code, timeout_ms }
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

WSL2 measurements on the restored kernel are in the low single-digit seconds with cold boots and full-copy image clone.

- Python p50: about 3.5s to 6.2s depending on timeout budget and host load.
- Bash p50: about 3.0s.

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

### `GET /health`

Response body:

```json
{
  "status": "ok",
  "worker_slots_available": 5,
  "worker_slots_total": 5
}
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
sudo env "PATH=$PATH" /tmp/aegis-bin --db 'postgres://postgres:postgres@localhost/aegis?sslmode=disable'
```

Example request:

```bash
curl -s -X POST http://localhost:8080/v1/execute \
  -H "Content-Type: application/json" \
  -d '{"lang":"python","code":"print(1)","timeout_ms":8000}' | jq .
```

## Roadmap

- v1 - shipped: Python + bash execution, worker pool, auth, audit log.
- v1.5 - in progress: overlayfs fast boot, PID 1 zombie reaping.
- v2 - planned: vsock HTTP proxy for package install support, YAML policy engine.
- v3 - planned: GitHub IAM proxy for credential isolation.
