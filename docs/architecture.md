# Aegis Architecture

This document describes the current Aegis stack as it exists today. It is meant to help an engineer understand the real execution path quickly.

## System Overview

```text
Client (browser / CLI / API consumer)
        |
        | HTTP
        v
+--------------------------------------+
| Orchestrator (Go)                    |
| - request validation                 |
| - worker slot pool                   |
| - policy resolution                  |
| - telemetry bus + SSE                |
| - receipt + stats assembly           |
| - audit record writes                |
+--------------------------------------+
        |
        | Firecracker control API
        v
+--------------------------------------+
| Firecracker microVM                  |
| - machine config from profile        |
| - rootfs + scratch + optional ws     |
| - optional TAP-backed networking     |
+--------------------------------------+
        |
        | Unix-socket vsock proxy
        v
+--------------------------------------+
| guest-runner                         |
| - reads execution payload            |
| - runs python / bash / node          |
| - emits stdout / stderr / done       |
| - emits guest PID telemetry          |
+--------------------------------------+
```

## Major Components

### API and Orchestrator

Source:
- [main.go](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\cmd\orchestrator\main.go)
- [handler.go](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\internal\api\handler.go)

Responsibilities:
- validate requests
- enforce worker-slot limits
- resolve policy and compute profile
- create an execution bus keyed by `execution_id`
- boot Firecracker
- attach host cgroups
- connect to the guest over Firecracker's Unix-socket vsock proxy
- aggregate guest chunks into a final result
- emit telemetry, receipts, and stats
- write execution records to Postgres

Important public endpoints:
- `POST /v1/execute`
- `POST /v1/execute/stream`
- `GET /v1/events/{exec_id}`
- `GET /v1/stats`
- `GET /health`
- `GET /ready`
- `GET /metrics`
- `DELETE /v1/workspaces/{id}`

### Worker Slots

Source:
- [pool.go](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\internal\executor\pool.go)

The worker pool is a bounded concurrency gate. It prevents the orchestrator from trying to boot too many microVMs at once and returns `429` on overflow.

This is operationally important because:
- Firecracker boot is not free
- teardown has to complete cleanly
- the proving ground should fail bounded, not melt under parallel abuse

### Firecracker VM Lifecycle

Source:
- [firecracker.go](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\internal\executor\firecracker.go)
- [lifecycle.go](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\internal\executor\lifecycle.go)

The executor creates a per-run VM with:
- a Firecracker machine config
- a rootfs
- a scratch disk path
- a vsock device
- optional network configuration

The VM lifecycle is:
1. allocate scratch and socket paths
2. start Firecracker
3. configure machine shape
4. configure rootfs and vsock
5. start the guest
6. attach cgroups
7. execute payload over vsock
8. tear down TAP, cgroup, sockets, scratch, and process state

Teardown is part of the product. The final receipt is emitted after cleanup state is known.

### Guest Runner

Source:
- [main.go](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\guest-runner\main.go)

`guest-runner` is a separate statically built Go binary that runs inside the VM.

Responsibilities:
- accept the execution payload
- optionally set up guest networking
- write the payload to a temp file
- launch the interpreter as an unprivileged user
- capture stdout / stderr
- emit bounded guest chunks back to the host
- emit guest PID telemetry for process-count demos
- return final exit metadata

This separation matters because:
- the guest execution path stays distinct from the host control plane
- guest transport and process handling can be tested independently
- the guest binary can stay lean and self-contained

### Vsock Transport

Source:
- [vsock.go](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\internal\executor\vsock.go)

The host does not dial guest `AF_VSOCK` directly. It connects through Firecracker's Unix-socket vsock proxy and then exchanges newline-delimited JSON guest chunks.

Guest chunk types include:
- `stdout`
- `stderr`
- `done`
- `telemetry`
- `error`

Host-side result assembly:
- aggregates stdout and stderr
- tracks raw output byte counts
- enforces `maxOutputBytes`
- marks `output_truncated`
- emits exit telemetry

The host-side transport has an explicit guest message size cap. This is a hardening measure, not a convenience feature.

### Telemetry Bus and SSE

Source:
- [bus_registry.go](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\internal\api\bus_registry.go)
- [telemetry_handler.go](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\internal\api\telemetry_handler.go)
- [event.go](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\internal\telemetry\event.go)

Each execution can have an in-memory telemetry bus keyed by `execution_id`.

That bus powers:
- `GET /v1/events/{exec_id}`
- receipt emission
- live proving-ground updates
- stats derivation

The proving ground intentionally subscribes before execution starts so it can show boot and early policy decisions rather than only tail output.

### Receipts and Stats

Source:
- [types.go](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\internal\models\types.go)
- [stats.go](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\internal\api\stats.go)

The containment receipt is the final execution summary. It includes:
- policy version and active profile
- network summary
- exit state
- cleanup result
- final verdict

`/v1/stats` is derived from completed receipts and is intentionally lightweight. It is useful for demos and live status, not as a historical analytics system.

### Storage Model

Current storage pieces:
- rootfs image
- per-run scratch state
- optional named workspace images
- Postgres audit records

Important truth:
- Aegis does not use snapshots today
- cold start is still dominated by VM boot plus current storage setup
- workspace durability exists, but cleanup semantics still need polish

## Policy Path

Source:
- [policy.go](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\internal\policy\policy.go)
- [allowlist-validation-policy.yaml](C:\Users\Cellardoor\Documents\Playground\.tmp\aegis-lite\configs\allowlist-validation-policy.yaml)

Policy covers:
- allowed languages
- max code size
- timeout bounds
- network mode and allowed domains
- cgroup resource values
- compute profile definitions

Important distinction:
- compute profiles currently affect Firecracker machine shape
- cgroup values are still policy-wide

So profile selection changes the VM shape, but not the full host resource envelope.

## Network Path

Current network modes:
- `none`
- `allowlist`

In `allowlist` mode:
- guest DNS is intercepted per execution
- allowlisted domains resolve
- resolved IPs trigger outbound allow rules
- denied domains do not install those rules
- network decisions are surfaced in telemetry and receipts

This is the strongest public demo story in the current stack.

## Current Default Behavior

- if the request omits `profile`, the API defaults to `nano`
- the proving ground does not currently expose profile selection directly
- the proving ground therefore runs on `nano` unless another client sets `profile`

This is intentional enough to document, but still worth revisiting later if profile exposure becomes part of the demo story.

## What the Architecture Does Not Claim

- Memory Pressure is not documented as a kernel OOM-kill path
- compute profiles are not documented as full cgroup envelopes
- snapshot-based cold boot is not documented as implemented
- Node is not documented as equally battle-tested with Python and bash

Those distinctions matter. This repo is strongest when the docs match the measured system instead of describing the ideal one.
