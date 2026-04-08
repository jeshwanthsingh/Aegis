# EXECUTION_LOG.md
## 2026-04-07 Initial /ai/ setup
- Created /ai/ workflow structure
- Completed: telemetry event bus, cgroup poller, SSE endpoint,
  containment receipt generation, end-to-end demo tests passing
- Pending: frontend UI, security audit

## 2026-04-08 Phase 1 - Schemas First
- Implemented: Phase 1 brief in `ai/CURRENT_PHASE.md`; added `schemas/intent-v1.json`, `schemas/event-v1.json`, `schemas/violation-v1.json`, `schemas/receipt-predicate-v1.json`; added `docs/v2/cedar-compilation-target.md` and `docs/v2/in-toto-mapping.md`
- Verified: JSON files parsed successfully with Python `json.tool`; schema surface checked against the locked v2 design and phase scope
- Skipped: runtime/backend changes, Cedar execution code, signing code, divergence logic, OTel export, attestation plumbing - deferred because Phase 1 is contract freeze only
- Assumptions: `gvisor` is a valid future-facing backend enum in v1 schemas; output artifacts remain canonically bound in in-toto `subject[]`; summary objects stay compact and do not attempt to encode raw event streams

## 2026-04-08 Phase 2 - Firecracker Sensor MVP
- Implemented: guest-side `/proc`-based runtime sensor scaffold in `guest-runner/runtime_sensor.go`; host-side RuntimeEvent normalization in `internal/executor/runtime_events.go`; vsock ingestion for batched runtime telemetry in `internal/executor/vsock.go`; internal RuntimeEvent model and telemetry kinds; integration demo script `tests/integration/runtime_events.sh`
- Verified: `/home/cellardoor/local/go/bin/go test ./...`; `cd guest-runner && /home/cellardoor/local/go/bin/go test ./...`; `/home/cellardoor/local/go/bin/go build -buildvcs=false ./cmd/orchestrator`
- Skipped: live Firecracker execution verification on this machine - `scripts/preflight.sh` failed at `/dev/kvm` access because WSL requires interactive sudo for KVM access in the current environment
- Assumptions: Phase 2 uses the existing JSON chunk protocol with compact batched telemetry; host-side normalization owns `seq` and `dropped_since_last`; selected file/network visibility is sampled from guest `/proc` state rather than eBPF in this MVP


## 2026-04-08 Phase 2 - Firecracker validation debug pass
- Implemented: fixed `tests/integration/runtime_events.sh`; added `tests/integration/runtime_events_manual.sh`; added targeted runtime sensor status breadcrumbs in `guest-runner/runtime_sensor.go`, `internal/executor/runtime_events.go`, and `internal/telemetry/event.go`; refreshed the baked `guest-runner` inside `assets/alpine-base.ext4`; brought guest loopback up before user code in `guest-runner/main.go`
- Verified: `bash -n tests/integration/runtime_events.sh`; `bash -n tests/integration/runtime_events_manual.sh`; `/home/cellardoor/local/go/bin/go test ./internal/executor ./internal/telemetry ./internal/api ./internal/models`; `cd guest-runner && /home/cellardoor/local/go/bin/go test ./...`; real Firecracker runs emitted normalized `runtime.event.v1` with `process.exec`, `process.fork`, `process.exit`, and `file.open`
- Skipped: Phase 2 closure - `net.connect` is still not emitted reliably from the temporary `/proc` socket path, so the live validation is still provisional
- Assumptions: the original Phase 2 failure was partly caused by a stale `guest-runner` binary baked into the rootfs; loopback availability is part of the guest execution baseline; the current `/proc` socket visibility path is still scaffolding and not production-grade


## 2026-04-08 Phase 2 - ptrace guest sensor pass
- Implemented: added `guest-runner/runtime_trace.go` with a ptrace-based process/connect sensor for `process.exec`, `process.fork`, `process.exit`, and `net.connect`; updated `guest-runner/main.go` to launch the traced workload and wait on tracer-owned exit state; reduced `guest-runner/runtime_sensor.go` to `/proc`-based `file.open` fallback plus batching/drop accounting; updated `tests/integration/runtime_events.sh` and `tests/integration/runtime_events_manual.sh` to use a deterministic Python loopback connect probe; rebaked the new `guest-runner` into `assets/alpine-base.ext4`
- Verified: `bash -n tests/integration/runtime_events.sh`; `bash -n tests/integration/runtime_events_manual.sh`; `/home/cellardoor/local/go/bin/go test ./internal/executor ./internal/telemetry ./internal/api ./internal/models`; `cd guest-runner && /home/cellardoor/local/go/bin/go test ./...`; `cd guest-runner && /home/cellardoor/local/go/bin/go build -buildvcs=false -a -o guest-runner .`
- Skipped: final real Firecracker proof on this machine - a fresh orchestrator instance now fails without privileged cgroup access (`open /sys/fs/cgroup/aegis/cgroup.subtree_control: permission denied`), and non-interactive sudo is unavailable here
- Assumptions: ptrace is the smallest production-minded direct sensor path that fits Phase 2 without introducing guest kernel tooling; `/proc` remains acceptable only as temporary `file.open` fallback

## 2026-04-08 Phase 2 - closure pass
- Implemented: added `scripts/rebake-guest-runner.sh` and baked `/etc/aegis-guest-runner.json` metadata into `assets/alpine-base.ext4`; made cgroup parent configurable in `internal/executor/lifecycle.go`; updated `cmd/orchestrator/main.go`, `scripts/preflight.sh`, `scripts/validate-phase2-runtime-events.sh`, `scripts/smoke-local.sh`, and `tests/integration/smoke.sh` to use the configurable parent; switched the canonical validation path to a delegated user scope so Firecracker keeps `/dev/kvm` access; tightened `guest-runner/main.go`, `guest-runner/runtime_trace.go`, and `tests/integration/runtime_events.sh` while debugging the real ptrace/connect path
- Verified: `./scripts/preflight.sh` passed; `./scripts/rebake-guest-runner.sh` rebaked the guest binary and emitted sha256/build-id metadata; `/home/cellardoor/local/go/bin/go test ./internal/executor ./internal/telemetry ./internal/api ./internal/models` passed after the cgroup-parent fix; `cd guest-runner && /home/cellardoor/local/go/bin/go test ./...` passed after the ptrace fixes; `bash -n scripts/validate-phase2-runtime-events.sh`; `bash -n scripts/smoke-local.sh`; `bash -n tests/integration/runtime_events.sh`; real Firecracker validation under `./scripts/validate-phase2-runtime-events.sh` proved `runtime.event.v1` for `process.exec`, `process.fork`, and `process.exit` using the freshly rebaked guest binary
- Skipped: Phase 2 closure; the real Firecracker proof still does not emit `net.connect`, so `tests/integration/runtime_events.sh` remains red by design and Phase 2 cannot honestly be marked complete
- Assumptions: `/proc` remains temporary `file.open` fallback only; delegated user scopes are the current local-dev path that preserves both cgroup delegation and `/dev/kvm` access; the remaining blocker is the AF_INET connect probe/sensor path rather than rootfs freshness or cgroup setup

## 2026-04-08 Phase 2 - AF_INET connect closure
- Implemented: tightened `guest-runner/runtime_trace.go` so child tracees treat plain `SIGTRAP`/`cause=0` stops as syscall stops; simplified `tests/integration/runtime_events.sh` to use a direct bash `/dev/tcp/127.0.0.1/17777` AF_INET connect attempt instead of the slower Python probe
- Verified: `cd guest-runner && /home/cellardoor/local/go/bin/go test ./...`; `cd ~/aegis && ./scripts/validate-phase2-runtime-events.sh`; real Firecracker validation passed and proved `runtime.event.v1` for `process.exec`, `process.fork`, `process.exit`, and `net.connect`
- Skipped: all Phase 3 work and all non-Phase-2 cleanup