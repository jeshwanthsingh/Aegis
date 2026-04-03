# Current Stack Benchmarks

These numbers are measured observations on the current Aegis stack. They are useful for demo planning and engineering comparison, not as universal guarantees.

## Scope

Current benchmark notes cover:
- repeated cold-start medians for `nano`, `standard`, and `crunch`
- current profile interpretation
- current demo-default recommendation

They do not claim:
- snapshot-based startup
- universal latency across machines
- profile-specific cgroup envelopes

## Repeated Medians

Minimal payload used for repeated medians:

```python
print("HELLO")
```

Measured medians, 5 runs each:

| Profile | Boot to `vm.boot.ready` | Total duration | Cleanup duration |
| --- | --- | --- | --- |
| `nano` | `1496ms` | `1632ms` | `290ms` |
| `standard` | `1601ms` | `1751ms` | `282ms` |
| `crunch` | `1867ms` | `2029ms` | `311ms` |

Interpretation:
- `nano` is the fastest measured default
- `standard` is only modestly slower
- `crunch` is slower on the current stack

## Profile Reality

Current built-ins:
- `nano` -> 1 vCPU / 128 MiB
- `standard` -> 2 vCPU / 512 MiB
- `crunch` -> 4 vCPU / 2048 MiB

Current truthfulness note:
- profiles affect Firecracker VM shape
- profiles do not yet change host cgroup policy

So they are real, but they are not full resource envelopes yet.

## Current Recommendation

Recommended demo default:
- `nano`

Why:
- it is the current default
- it is the fastest measured profile on this stack
- it matches the proving-ground demo story best

Current judgment on `crunch`:
- worth keeping as an engineering option
- not the recommended public demo default on the current stack

## Benchmark Caveats

- These numbers are from the current stack, not a universal baseline.
- Cleanup timing is useful, but less stable than boot and total duration.
- More repeated runs and more scenario-specific medians are still worth adding.
- Snapshot and cold-start optimization are future work, not part of the current benchmark story.

## Follow-up Work

- add repeated-run medians for strong proving-ground presets
- expand cold-start measurement coverage
- benchmark future snapshot/resume work separately if it lands
