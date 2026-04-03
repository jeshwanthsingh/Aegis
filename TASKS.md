# Aegis Task Tracker

## Complete

### Runtime and control plane
- [x] Firecracker microVM execution
- [x] worker slot pool with `429` on overflow
- [x] PostgreSQL audit log and execution state handling
- [x] YAML policy engine
- [x] cgroups v2 enforcement for memory, CPU, PID, and swap policy
- [x] deterministic teardown and startup reconciliation
- [x] scratch execution model
- [x] streaming execution path
- [x] persistent workspaces
- [x] `aegis-cli`

### Proving ground
- [x] proving-ground minimum viable flow
- [x] predeclared `execution_id` plus pre-subscribe SSE
- [x] live event stream rendering
- [x] execution output rendering
- [x] containment receipt rendering
- [x] live `/v1/stats`
- [x] preset cleanup
  - [x] Allowed DNS
  - [x] Denied DNS
  - [x] Fork Bomb with `pids_limit`
  - [x] Memory Pressure conservative wording
  - [x] Blocked Outbound Connect
  - [x] Huge Stdout with truncation

### Receipts, stats, and telemetry
- [x] `containment.receipt` includes network summary
- [x] `/v1/stats` derived from completed receipts
- [x] `/ready`
- [x] `/metrics`
- [x] structured JSON logging on hot paths

### Hardening
- [x] workspace path traversal / host file clobber fix
- [x] Firecracker environment inheritance tightening
- [x] timeout lower-bound validation
- [x] SSE waiter cap and shorter missing-execution wait
- [x] host-side vsock message size limit
- [x] install-time checksum verification
- [x] `npm` removed from guest image while preserving Node execution support

### Compute-profile truthfulness
- [x] locate and document profile source of truth
- [x] validate `nano`, `standard`, and `crunch`
- [x] surface active profile in receipt and proving-ground UI
- [x] document current default profile
- [x] make docs explicit that profiles currently change VM shape, not cgroup policy
- [x] recommend `nano` as current demo default

### Nano Huge Stdout fix
- [x] reproduce `nano` Huge Stdout failure directly via API
- [x] isolate the runtime transport issue
- [x] fix the Huge Stdout path for `nano`
- [x] add a targeted regression test

## In Progress

- [ ] docs polish and demo assets
- [ ] benchmark documentation expansion
- [ ] workspace durability cleanup
- [ ] observability cleanup

## Next Decisions

### Compute profile semantics
- [ ] decide whether profiles remain VM-shape-only
- [ ] or become full resource envelopes that also change cgroup policy

### Demo productization
- [ ] decide whether the proving ground should expose a profile selector later
- [ ] decide how much public-demo operational hardening still belongs before broader launch

### Performance work
- [ ] expand repeated benchmark docs and medians
- [ ] extend cold-start benchmarking coverage
- [ ] investigate snapshots / resume as future work

## Documentation and Assets

- [ ] capture current screenshots for:
  - [ ] proving-ground idle state
  - [ ] Allowed DNS
  - [ ] Denied DNS
  - [ ] Fork Bomb with `pids_limit`
  - [ ] Huge Stdout with `output_truncated`
  - [ ] Blocked Outbound Connect
- [ ] add short GIFs only after the screenshots are current
- [ ] keep benchmark docs aligned with measured numbers only

## Deferred

- [ ] snapshot-based startup
- [ ] broader workspace durability redesign
- [ ] full vsock HTTP proxy
- [ ] filesystem jail inside the guest
- [ ] broader IAM / identity integrations

## Notes

- The system is demo-real today: live microVMs, live telemetry, live receipts, and live stats all work together.
- The strongest public demo path today is:
  - Allowed DNS
  - Denied DNS
  - Fork Bomb
  - Huge Stdout
  - Blocked Outbound Connect
- Memory Pressure remains useful, but should stay conservatively framed.
