# Aegis — Task Tracker

## Done
- [x] v1: Firecracker microVM execution (Python, bash)
- [x] v1: Worker pool (5 concurrent slots), 429 on overflow
- [x] v1: API key auth, GET /health endpoint
- [x] v1: Audit log (PostgreSQL), execution state machine
- [x] v1: cgroup v2 limits (memory, CPU, pids), no-network default
- [x] v1: Deterministic teardown, startup reconciliation
- [x] v1.5: Two-drive overlayfs (read-only base + 50MB scratch per execution)
- [x] v1.5: PID 1 zombie reaping (SIGCHLD + Wait4 in guest-runner)
- [x] v2: YAML policy engine (allowed languages, resource limits, max timeout)
- [x] v2: aegis-cli
- [x] v2: Streaming I/O / SSE path
- [x] v2.1: Compute profiles
  - [x] Added profile-aware API request handling
  - [x] Added default profiles: nano (1 vCPU / 128MB), standard (2 vCPU / 512MB), crunch (4 vCPU / 2048MB)
  - [x] Firecracker machine-config now uses profile VCPU and memory values
  - [x] Invalid profiles fail fast with `invalid compute profile`
  - [x] Verified in guest: nano reports 1 CPU / ~112MB, standard reports 2 CPU / ~490MB
- [x] v2.2: Persistent workspaces
  - [x] Added host-side reusable ext4 workspace disks under `/tmp/aegis/workspaces`
  - [x] Added `workspace_id` API support and `DELETE /v1/workspaces/{id}`
  - [x] Guest runner now mounts `/dev/vdb` at `/workspace`
  - [x] Verified persistence across executions: write in VM 1, read in VM 2
  - [x] Verified ephemeral runs still do not persist workspace state
- [x] README, install flow, OpenClaw docs, and CI workflow scaffolded
- [x] Core demo tests 1-4 passing on WSL2
- [x] GitHub Actions workflow YAML syntax fixed and validated locally

## In Progress
- [ ] GitHub Actions CI stabilization
  - Core demo tests are split cleanly from isolated-mode checks
  - Workflow now parses correctly again after removing corrupted non-ASCII text
  - Remaining work is isolated-mode rule verification, not YAML or boot-time failures
- [ ] Core runtime validation hardening
  - [ ] Split CI into build/boot, core-demo, and isolation-check jobs
  - [ ] Make bash + python execution mandatory green checks
  - [ ] Verify audit log row creation and teardown on every CI run
  - [ ] Verify 429 overflow behavior under worker pool saturation

## Up Next (priority order)

### 1. GitHub Actions CI — 1 day
- [ ] Make CI green on real Linux runners
- [ ] Keep the badge honest: prove build, boot, DB, and core demo flow work end-to-end
- [ ] Stabilize the isolated-mode verification around valid host-side firewall checks

### 2. DNS interception — 3 days
- [ ] Replace brittle domain allowlist logic with DNS-layer interception
- [ ] Resolve preset policy at the DNS boundary instead of hardcoding destination IPs
- [ ] Keep host-side enforcement as the source of truth
- [ ] Use this as the cleaner replacement for the current allowlist approach

### 3. Crunch profile validation follow-up
- [ ] Re-test `crunch` with a higher timeout (20s+) on WSL2 and Linux CI
- [ ] Decide whether `crunch` needs a profile-specific timeout recommendation or CI exemption
- [ ] Add a stronger kernel-level memory pressure test if we want OOM-kill proof beyond Python `MemoryError`

### 4. Workspace durability cleanup
- [ ] Investigate why the second successful workspace read still reports `exit_code: 1`
- [ ] Decide whether this is guest-runner cleanup noise or a shell-level nonzero exit worth surfacing differently

## Deferred
- Node.js on WSL2 — still sensitive to guest entropy/runtime behavior
- Full vsock HTTP proxy (pip install support) — useful, but more moving parts than CI stabilization
- Filesystem jail inside guest — better as a dedicated follow-up after workspaces land
- GitHub IAM proxy — strong v3 feature, separate trust boundary
- Firecracker snapshots — operationally valuable, but not the best immediate leverage

## Notes
- The project is already beyond toy stage: it boots real microVMs, executes untrusted code, enforces cgroup limits, tears down cleanly, and has a policy surface
- The weakest area right now is not the core execution model; it is validation/operability on real Linux CI and the next layer of product polish
- Default direction should remain: host-enforced isolation first, guest behavior second
- Compute profiles and persistent workspaces are platform-hardening work: they increase utility without weakening the VM boundary
