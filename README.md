[![CI](https://github.com/jeshwanthsingh/Aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/jeshwanthsingh/Aegis/actions/workflows/ci.yml)
# Aegis

Aegis is a self-hostable Firecracker-backed execution plane for running untrusted AI-generated code inside disposable microVMs instead of on the host.

It is built for the boring failures that actually matter in agent systems: runaway code, resource abuse, accidental host access, accidental egress, and dirty teardown.

Read these first:
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md)
- [docs/alpine-rootfs-migration.md](docs/alpine-rootfs-migration.md)

## Architecture

```text
Agent / CLI / API client
        |
        | POST /v1/execute
        v
+-----------------------------+
| Aegis orchestrator (Go)     |
| - policy enforcement        |
| - worker pool               |
| - audit log                 |
| - metrics / ready / health  |
+-----------------------------+
        |
        | boot Firecracker VM
        v
+-----------------------------+
| Firecracker microVM         |
| - cgroup limits on host     |
| - scratch disk / workspace  |
| - optional DNS allowlist    |
+-----------------------------+
        |
        | virtio-vsock
        v
+-----------------------------+
| guest-runner                |
| - exec python / bash / node |
| - capture stdout / stderr   |
| - return exit status        |
+-----------------------------+
```

## What It Protects Against

Aegis is meant to reduce blast radius for:
- untrusted generated code
- CPU, memory, PID, and timeout abuse
- accidental network egress
- persistent host residue after execution

It is not a solution for prompt injection, supply-chain trust, IAM, or model correctness. The blunt version is in [THREAT_MODEL.md](THREAT_MODEL.md).

## Install

Primary path:

```bash
bash scripts/install.sh
```

Preflight only:

```bash
./scripts/preflight.sh
```

One-command local doctor:

```bash
./scripts/smoke-local.sh
```

Rebuild the Alpine candidate rootfs:

```bash
./scripts/build-alpine-rootfs.sh --output assets/alpine-base.ext4 --backup-existing assets/ubuntu-legacy.ext4
```

Build the real Alpine/musl guest image:

```bash
./scripts/build-alpine-rootfs.sh
```

### Requirements
- Linux with KVM available at `/dev/kvm`
- Firecracker installed
- PostgreSQL available
- guest assets in `assets/`

WSL2 works for development, but native Linux is the cleaner target. See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

For migration or rollback testing, start Aegis with an explicit rootfs override:

```bash
/tmp/aegis-bin --db "$DB_URL" --assets-dir "$PWD/assets" --rootfs-path "$PWD/assets/alpine-base.ext4"
```

During the rootfs migration, the legacy image remains the default. To validate the new Alpine image without changing defaults, run Aegis with `AEGIS_ROOTFS_PATH=/absolute/path/to/alpine-musl.ext4`.

## One-Command Demo

With the orchestrator running on `localhost:8080`:

```bash
curl -s -X POST http://localhost:8080/v1/execute \
  -H "Content-Type: application/json" \
  -d '{"lang":"python","code":"print(1)","timeout_ms":8000}'
```

Expected shape:

```json
{
  "stdout": "1\n",
  "stderr": "",
  "exit_code": 0,
  "duration_ms": 6223,
  "execution_id": "023ebc28-dca0-4241-a5ae-ff4ed4f51505"
}
```

## Local Validation

Aegis now has two integration scripts that prove the core system works:

```bash
BASE_URL=http://localhost:8080 tests/integration/smoke.sh
BASE_URL=http://localhost:8080 tests/integration/abuse.sh
```

`smoke.sh` covers:
- health
- bash execute
- python execute
- timeout enforcement
- concurrency and 429 overflow
- teardown verification
- allowlist DNS resolve and deny

`abuse.sh` covers:
- fork bomb containment
- infinite loop containment
- memory abuse containment
- huge stdout truncation
- process explosion containment
- post-abuse health

## API

### `POST /v1/execute`

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
- `profile`
- `workspace_id`

### `GET /health`
Returns process health and worker-slot counts.

### `GET /ready`
Returns ready only when the orchestrator can talk to Postgres and has worker capacity available.

### `GET /metrics`
Returns Prometheus-style metrics for executions, boot, teardown, and worker-slot availability.

### `DELETE /v1/workspaces/{id}`
Deletes a persistent workspace image.

## CLI

```bash
aegis health
aegis run --lang python --code "print('hello')"
aegis run --lang bash --file script.sh
aegis run --lang python --code "..." --stream
```

## OpenClaw Integration

Aegis ships an OpenClaw skill so the agent can execute code in a disposable microVM rather than on the host machine.

Quick setup:

```bash
mkdir -p ~/.openclaw/workspace/skills/aegis-exec
curl -L https://raw.githubusercontent.com/jeshwanthsingh/Aegis/main/openclaw-plugin/SKILL.md \
  -o ~/.openclaw/workspace/skills/aegis-exec/SKILL.md
```

See `docs/openclaw-integration.md` for the full setup flow.

## Roadmap

- v1 — shipped: Python + bash execution, worker pool, audit logging, cgroup enforcement
- v2 — shipped: YAML policy engine, streaming I/O, CLI, compute profiles, persistent workspaces
- v3 — planned: vsock HTTP proxy for package installs
- v4 — planned: GitHub IAM proxy

## Rootfs Migration

A reproducible Alpine/musl rootfs build flow now exists in `scripts/build-alpine-rootfs.sh`.

The current default remains the legacy `assets/alpine-base.ext4` image for rollback safety. Use `AEGIS_ROOTFS_PATH` to opt into a real Alpine image during migration validation. See `docs/alpine-rootfs-migration.md` for the migration notes, parity checklist, and benchmark guidance.
