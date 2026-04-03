[![CI](https://github.com/jeshwanthsingh/Aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/jeshwanthsingh/Aegis/actions/workflows/ci.yml)
# Aegis

Firecracker-backed containment for untrusted AI-generated code.

Aegis is a Go-based execution plane that runs generated code inside disposable Firecracker microVMs instead of on the host. It is built for the failures that actually show up in agent systems: runaway code, accidental egress, dirty teardown, oversized output, and resource abuse that should be contained instead of trusted.

Read these first:
- [docs/proving-ground.md](docs/proving-ground.md)
- [docs/architecture.md](docs/architecture.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md)
- [docs/benchmarks/current-stack.md](docs/benchmarks/current-stack.md)

## Why it exists

Most agent tooling still assumes generated code can be run on the host or inside light process isolation. That is enough for demos, but weak for systems that need to survive bad code, bad prompts, or hostile inputs.

Aegis exists to make the boundary real:
- KVM-backed Firecracker microVM per execution
- cgroups v2 for host-side CPU, memory, and PID control
- virtio-vsock for host/guest transport
- deterministic teardown of scratch disks, TAP state, sockets, and cgroups
- a proving ground that shows the containment path live instead of describing it after the fact

## Current Status

### Demo-ready now
- Firecracker/KVM execution is live.
- The proving ground is wired to the real backend.
- Predeclared `execution_id` plus pre-subscribe SSE is live.
- Containment receipts and in-memory `/v1/stats` are live.
- The strongest validated demo flows are:
  - Allowed DNS
  - Denied DNS
  - Fork Bomb with `pids_limit`
  - Huge Stdout with `output_truncated`
  - Blocked Outbound Connect

### Implemented and real, but still intentionally conservative
- Memory Pressure demonstrates safe failure under pressure. It should not be marketed as a kernel or cgroup OOM-kill proof.
- Compute profiles are real, but today they change Firecracker VM shape only. They do not yet change cgroup policy.
- Cold-start and snapshot optimization are still future work on this stack.

### What remains
- Demo assets: screenshots, GIFs, and presentation polish
- Expanded repeated benchmark documentation
- Decide whether compute profiles remain VM-shape-only or become full resource envelopes
- Cold-start benchmarking expansion and snapshot investigation
- A small amount of public-demo operational hardening and observability cleanup

## What the Proving Ground Demonstrates

The proving ground is the public demo surface for Aegis. It opens the event stream before execution starts, runs a real payload in a live microVM, and renders the receipt and aggregate stats after teardown.

The strongest presets are:
- `Allowed DNS`
  - Shows DNS allowlisting plus selective outbound rule installation.
- `Denied DNS`
  - Shows non-allowlisted resolution being denied cleanly.
- `Fork Bomb`
  - Shows guest PID cap containment and exits with `pids_limit`.
- `Huge Stdout`
  - Shows output truncation enforcement and `output_truncated`.
- `Blocked Outbound Connect`
  - Shows a blocked outbound socket attempt with a crisp user-visible result.
- `Memory Pressure`
  - Shows safe failure under pressure without overclaiming a stronger OOM story.

See [docs/proving-ground.md](docs/proving-ground.md) for the exact preset behavior, telemetry semantics, and what each preset does not prove.

## Key Features

- Disposable Firecracker microVM per execution
- Go orchestrator with bounded worker slots and explicit API surface
- cgroups v2 enforcement for memory, CPU, PID, and swap policy
- scratch/workspace execution model with deterministic cleanup
- virtio-vsock host/guest transport
- DNS allow/deny telemetry and selective egress rule installation in allowlist mode
- containment receipts with cleanup and network summaries
- in-memory `/v1/stats` derived from completed receipts
- proving ground UI with live SSE telemetry, execution output, receipts, and stats
- recent hardening around workspace paths, env inheritance, SSE waiting, vsock message sizing, and installer verification

## Architecture

```text
Browser / CLI / API client
        |
        | POST /v1/execute
        | POST /v1/execute/stream
        | GET  /v1/events/{exec_id}
        | GET  /v1/stats
        v
+----------------------------------+
| Aegis orchestrator (Go)          |
| - policy validation              |
| - worker slot pool               |
| - receipt + stats assembly       |
| - telemetry bus + SSE            |
+----------------------------------+
        |
        | boot Firecracker VM
        v
+----------------------------------+
| Firecracker microVM              |
| - profile-driven VM shape        |
| - host cgroup attachment         |
| - scratch filesystem / workspace |
| - optional TAP + DNS path        |
+----------------------------------+
        |
        | virtio-vsock
        v
+----------------------------------+
| guest-runner                     |
| - exec python / bash / node      |
| - capture stdout / stderr        |
| - emit guest chunks + telemetry  |
| - return exit metadata           |
+----------------------------------+
```

Full architecture notes: [docs/architecture.md](docs/architecture.md)

## Demo Scenarios

| Preset | What it demonstrates | What it does not prove |
| --- | --- | --- |
| Allowed DNS | DNS allowlist decision plus selective outbound rule installation | General internet access or arbitrary egress |
| Denied DNS | Non-allowlisted resolution is blocked | Broad firewall policy beyond the current allowlist path |
| Fork Bomb | PID cap containment with `pids_limit` | General kernel stability guarantees |
| Memory Pressure | Safe failure under memory pressure | A kernel OOM kill or stronger memory-isolation claim |
| Blocked Outbound Connect | Blocked outbound socket attempt with visible result | A broader outbound-control guarantee beyond the demonstrated blocked-connect path |
| Huge Stdout | Truncation enforcement with receipt evidence | Unlimited log streaming or full output preservation |

## Security Model

What Aegis enforces today:
- Isolation boundary: Firecracker microVM on KVM
- Host-side cgroups v2 for memory, CPU, PID, and swap policy
- Per-execution scratch state and deterministic teardown
- Default no-network or explicit allowlist network mode
- Host/guest transport over Firecracker's Unix-socket vsock proxy
- Containment receipts written after cleanup state is known

Recent hardening already landed:
- workspace path traversal / file clobber risk fixed
- Firecracker environment inheritance tightened
- SSE wait abuse reduced with waiter caps and shorter missing-execution waits
- host-side vsock guest message size cap
- install-time checksum verification in `scripts/install.sh`
- guest image surface reduced by removing `npm`

What should stay conservative:
- Memory Pressure is not currently a kernel OOM-kill proof.
- Compute profiles are not full resource envelopes yet.
- Snapshot-based cold boot is not implemented yet.

Security details and non-goals: [THREAT_MODEL.md](THREAT_MODEL.md)

## Quickstart

### Requirements
- Linux with KVM available at `/dev/kvm`
- Firecracker installed
- PostgreSQL available
- cgroups v2 enabled
- rootfs and kernel assets present in `assets/`

WSL2 works for development, but native Linux is the cleaner target. See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

### Install

```bash
bash scripts/install.sh
```

### Preflight

```bash
./scripts/preflight.sh
```

### Local doctor

```bash
./scripts/smoke-local.sh
```

### Run the proving ground locally

```bash
/tmp/aegis-bin \
  --db "$DB_URL" \
  --assets-dir "$PWD/assets" \
  --policy "$PWD/configs/allowlist-validation-policy.yaml" \
  --rootfs-path "$PWD/assets/alpine-base.ext4"
```

Then open:
- `GET /`
- `GET /health`
- `GET /ready`
- `GET /metrics`
- `GET /v1/stats`

### Rebuild the Alpine rootfs

```bash
./scripts/build-alpine-rootfs.sh \
  --output assets/alpine-base.ext4 \
  --backup-existing assets/ubuntu-legacy.ext4
```

## Proving-Ground Usage

Typical flow:
1. Open the proving ground.
2. Select a preset or edit the payload.
3. The UI predeclares an `execution_id` and subscribes to `GET /v1/events/{exec_id}`.
4. The UI submits the matching `POST /v1/execute` request.
5. Watch the event stream, execution output, containment receipt, and `/v1/stats`.

Useful endpoints:
- `POST /v1/execute`
- `POST /v1/execute/stream`
- `GET /v1/events/{exec_id}`
- `GET /v1/stats`
- `GET /health`
- `GET /ready`
- `GET /metrics`
- `DELETE /v1/workspaces/{id}`

The proving ground does not currently expose profile selection directly. If no `profile` is supplied, the API defaults to `nano`.

## Benchmark Notes

Measured repeated medians on the current stack with a minimal payload:
- `nano` -> boot `1496ms`, total `1632ms`, cleanup `290ms`
- `standard` -> boot `1601ms`, total `1751ms`, cleanup `282ms`
- `crunch` -> boot `1867ms`, total `2029ms`, cleanup `311ms`

These are observed numbers on the current stack, not universal guarantees.

Current benchmark conclusions:
- `nano` is the fastest measured default and the recommended demo profile.
- `standard` is real, but only modestly different under the current shared cgroup policy.
- `crunch` is slower today and not the recommended public demo default.

Benchmark details: [docs/benchmarks/current-stack.md](docs/benchmarks/current-stack.md)

## Compute Profiles

Profiles are defined in [internal/policy/policy.go](internal/policy/policy.go).

Current built-ins:
- `nano` -> 1 vCPU, 128 MiB
- `standard` -> 2 vCPU, 512 MiB
- `crunch` -> 4 vCPU, 2048 MiB

Current reality:
- profiles are applied to Firecracker machine config
- profiles are visible in the containment receipt and proving-ground receipt summary
- profiles do not currently change cgroup policy

So profiles are real today, but they describe VM shape, not the full runtime envelope.

## Limitations and Non-Goals

- Memory Pressure is a conservative safe-failure demo, not a polished OOM-kill proof.
- Compute profiles currently change VM shape only, not cgroup policy.
- Snapshots and cold-boot optimization are future work.
- WSL2 remains a development environment, not the cleanest performance baseline.
- Node is supported, but Python and bash remain the stronger execution paths.
- Persistent workspace durability cleanup is still not fully finished.

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for the current caveats.

## Roadmap

Near-term:
- polish demo assets and screenshots
- expand repeated benchmark docs
- decide whether compute profiles remain VM-shape-only or grow into full resource envelopes
- extend cold-start benchmarking
- investigate snapshot/resume as a future optimization path

Future work:
- snapshot-based startup
- profile-aware cgroup envelopes
- more deliberate proving-ground profile exposure
- additional public-demo operational hardening

## Screenshots

Suggested assets to add:
- proving-ground idle state
- Allowed DNS run with rule installation visible
- Denied DNS run with clean refusal
- Fork Bomb receipt showing `pids_limit`
- Huge Stdout receipt showing `output_truncated`
- Blocked Outbound Connect output

These should be captured from the live proving ground rather than mocked.
