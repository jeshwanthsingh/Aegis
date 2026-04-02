# Aegis Architecture

## Purpose
Aegis runs untrusted AI-generated code inside disposable Firecracker microVMs so execution is isolated from the host and every run produces an audit record.

## System Boundaries
- Host control plane: Go HTTP API that creates, runs, and tears down VMs.
- Isolation boundary: Firecracker microVM with KVM-backed hardware isolation.
- Guest runtime: `guest-runner/` binary inside the VM that executes payloads and returns results.
- Persistence layer: PostgreSQL audit log for execution outcomes and recovery state.

## Execution Flow
1. The control plane receives an execution request.
2. A scratch root filesystem is prepared for the run.
3. Firecracker is started over its Unix socket control API.
4. The VM boots with a guest CID configured for vsock transport.
5. The host connects to the Firecracker vsock Unix socket proxy and requests the guest port.
6. The payload is sent to the guest runner.
7. The guest runner executes the payload and returns output and metadata.
8. The control plane tears down sockets, process state, cgroups, and scratch artifacts.
9. The final execution status is recorded in Postgres after teardown state is known.

## Host/Guest Boundary
- The host does not dial `AF_VSOCK` directly.
- Host-side communication uses Firecracker's Unix socket vsock proxy protocol.
- The guest listens on a fixed vsock port.
- The guest CID is currently configured explicitly during boot.

## Resource Model
- cgroup v2 enforces memory, CPU, process-count, and swap limits.
- Resource limits must be established before attaching the VM process to the cgroup.
- Cleanup must remove cgroup state and socket artifacts reliably to avoid host leakage across runs.

## Storage Model
- The current implementation uses a full-copy scratch image workflow.
- Cold-boot performance is therefore dominated by VM boot plus rootfs clone time.
- Faster snapshot or overlay-based startup is a future optimization path, not the current architecture.

## Audit and Recovery
- Postgres stores execution outcome, status, duration, and output metadata.
- Startup reconcile logic repairs in-progress state after crashes or interrupted runs.
- Audit records should reflect the final teardown-confirmed state, not a guessed intermediate state.
