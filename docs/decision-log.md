# Aegis Decision Log

## Firecracker Kernel
- Decision: use a pre-built AWS-compatible `vmlinux` binary.
- Why: kernel work is not the product value and would add unnecessary operational burden.

## Guest Runner Build
- Decision: keep `guest-runner/` as a separate Go module and build it statically with `CGO_ENABLED=0`.
- Why: it runs inside the VM and should stay isolated from orchestrator dependencies and host-specific build assumptions.

## Host/Guest Transport
- Decision: use Firecracker's Unix socket vsock proxy protocol on the host side.
- Why: this is the practical transport exposed by Firecracker in the current environment; direct host `AF_VSOCK` dialing is not the control-plane path here.

## Audit Ordering
- Decision: write final audit state only after teardown state is known.
- Why: partial cleanup and teardown failures materially change the execution outcome and must not be hidden by premature success logging.

## Teardown Language
- Decision: describe the current scratch-image workflow as a full copy, not copy-on-write.
- Why: the implementation uses byte-copy semantics today and the docs should stay honest about the performance implications.

## Resource Controls
- Decision: keep `pids.max` enforcement as a hard requirement.
- Why: it is the fork-bomb kill switch and must not be treated as optional hardening.

## Future Performance Work
- Decision: treat snapshots and overlay-style storage as a future optimization path.
- Why: current benchmark numbers are based on cold boot plus full-copy scratch images and should not be described as snapshot-based performance.
