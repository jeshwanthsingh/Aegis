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
- [x] README, install flow, OpenClaw docs, and CI workflow scaffolded
- [x] Core demo tests 1-4 passing on WSL2

## In Progress
- [ ] GitHub Actions CI stabilization
  - Core demo tests are split from isolation tests
  - Current blocker: isolated-mode firewall rules and CI assertions need one valid Linux-wide implementation path

## Up Next (priority order)

### 1. GitHub Actions CI — 1 day
- [ ] Make CI green on real Linux runners
- [ ] Keep the badge honest: prove build, boot, DB, and core demo flow work end-to-end
- [ ] Simplify isolated-mode verification so it checks valid firewall behavior without depending on flaky guest-side assumptions

### 2. Compute profiles — 2 days
- [ ] Add small/medium/large execution profiles
- [ ] Slot profiles into the existing YAML policy engine
- [ ] Map profiles cleanly onto cgroup memory/CPU/pids limits and timeouts
- [ ] Expose profile selection in API and aegis-cli without breaking default behavior

### 3. Persistent workspaces — 2 days
- [ ] Add optional reusable execution workspace state between runs
- [ ] Preserve files for agents that need iteration instead of one-shot execution
- [ ] Keep teardown and quota controls explicit so persistence does not weaken isolation guarantees
- [ ] Define lifecycle: create, reuse, expire, destroy

### 4. DNS interception — 3 days
- [ ] Replace brittle domain allowlist logic with DNS-layer interception
- [ ] Resolve preset policy at the DNS boundary instead of hardcoding destination IPs
- [ ] Keep host-side enforcement as the source of truth
- [ ] Use this as the cleaner replacement for the current allowlist approach

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