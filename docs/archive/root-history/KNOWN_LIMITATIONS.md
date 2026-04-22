# Known Limitations

This document is the short list of real caveats that still matter for Aegis today.

## Compute profiles are VM-shape-only today

Profiles are real:
- `nano` → 1 vCPU / 128 MiB
- `standard` → 2 vCPU / 512 MiB
- `crunch` → 4 vCPU / 2048 MiB

But today they only change Firecracker machine shape.

They do not yet change host cgroup policy:
- `memory.max`
- `memory.high`
- `pids.max`
- `cpu.max`
- `memory.swap.max`

So profiles are not full resource envelopes yet.

## Memory Pressure is intentionally conservative

The Memory Pressure preset is useful, but it should be described carefully.

What is proven:
- code can fail safely under memory pressure
- teardown still completes cleanly

What is not yet proven:
- a kernel OOM kill
- a cgroup OOM event
- a stronger memory-isolation claim than what has been directly observed

## Snapshots are not implemented yet

Aegis currently uses the existing cold-boot path. Snapshot-based startup, resume, or similar boot optimizations are future work.

That means:
- cold boot is still visible
- current benchmark numbers are about this stack, not a snapshot design

## WSL2 remains a development environment

WSL2 works for development and validation, but it is not the cleanest performance baseline.

Expect more edge cases around:
- KVM access
- networking behavior
- path and mount semantics
- timing variability

Native Linux remains the more reliable baseline for runtime and benchmark claims.

## Node is supported, but less battle-tested

Python and bash are the strongest execution paths today. Node remains supported, but it should not be described as equally battle-tested on every environment.

## Workspace durability cleanup still needs polish

Persistent workspaces exist, but workspace durability cleanup is still not fully finished. The data path is useful; the last bit of status correctness and cleanup polish is still open.

## Observability still has cleanup debt

The telemetry path is useful and real, but some debug-era presentation and logging cleanup still remains.

## Public demo operations still have follow-up work

The proving ground is live and useful, but a few things still belong on the follow-up list:
- more polished benchmark documentation
- demo assets and screenshots
- a clearer long-term decision on compute-profile semantics
- snapshot and cold-start investigation
