# Warm Pool v1

Warm pool reduces startup latency by keeping a small number of generic Firecracker microVMs prebooted and paused.

This is an optimization layer on top of the existing execution model. It is not a second runtime architecture.

## What warm pool does

- preboots paused microVMs in the background
- waits for guest-runner readiness before considering a VM available
- resumes one warm VM for one execution
- tears that VM down after the run
- replenishes the pool asynchronously
- falls back to cold boot whenever the warm path is unavailable or unsupported

## Current scope

Warm pool v1 is intentionally narrow.

Warm path applies to:

- default-profile scratch executions

Cold fallback still applies to:

- persistent workspace executions
- non-default compute profiles
- empty or stale pool states

That scope is deliberate. The current VM-creation seam binds workspace and profile characteristics at boot time, so Aegis treats warm pool as a limited latency optimization rather than overclaiming universal coverage.

## Configuration

Environment variables:

- `AEGIS_WARM_POOL_SIZE`
- `AEGIS_WARM_POOL_MAX_AGE`

Equivalent config file fields:

```yaml
runtime:
  warm_pool_size: 1
  warm_pool_max_age: 300
```

Defaults:

- `warm_pool_size: 0`
- `warm_pool_max_age: 300`

`warm_pool_size: 0` disables the feature.

## Operator visibility

`aegis serve` surfaces warm-pool posture directly in startup output.

HTTP health and readiness also expose warm-pool state:

- `enabled`
- `configured_size`
- `available`
- `initializing`
- `max_age_seconds`
- `warm_claims`
- `cold_fallbacks`
- `claim_errors`
- `recycled_expired`

Prometheus metrics include:

- `aegis_execution_path_total{path="warm|cold"}`
- `aegis_vm_ready_duration_seconds{path="warm|cold"}`

## Observed behavior

Warm pool is not theoretical in this repo state. The runtime has already shown real warm-path latency improvement on the validated path.

What that means in practice:

- warm startup is materially faster than cold boot for the supported path
- cold fallback remains part of normal operation
- the right expectation is “faster when the request fits the warm path,” not “all requests are warm”

## Security and correctness

Warm pool does not broaden the trust model:

- execution still happens in Firecracker microVMs
- receipts and proof bundles are still emitted normally
- broker behavior and divergence handling remain on the normal path
- a warm VM is not reused after it has run untrusted code

## Caveats

- no snapshot/restore path exists here; this is pause/resume only
- warm coverage is not universal across all request shapes
- warm pool is an optimization, not a separate product surface
- if the pool cannot satisfy a request, Aegis falls back to the existing cold path instead of failing closed on availability grounds
