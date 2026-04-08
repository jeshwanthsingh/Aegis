# Phase 2 - Firecracker Sensor MVP

## Status
Complete.

## Goal Achieved
A real Firecracker run now emits normalized `runtime.event.v1` records for:
- `process.exec`
- `process.fork`
- `process.exit`
- `net.connect`

## Notes
- The guest binary rebake path is reproducible and freshness is baked into the rootfs via `/etc/aegis-guest-runner.json`.
- Cgroup parent selection is configurable and validated against a delegated writable subtree.
- `/proc` remains temporary `file.open` fallback only.

## Deferred
- Cedar and divergence logic
- gVisor
- receipt/signing changes
- attestation
- OTel export
- `file.open` replacement

## Next
Await the Phase 3 brief. Do not start Phase 3 work without a new current-phase update.