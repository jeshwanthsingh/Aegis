# Aegis - Task Tracker

## Done
- [x] v1: Firecracker microVM execution (Python, bash)
- [x] v1: Worker pool (5 concurrent slots), 429 on overflow
- [x] v1: API key auth and GET /health
- [x] v1: PostgreSQL audit log and execution state machine
- [x] v1: cgroup v2 limits (memory, CPU, pids) with no-network default
- [x] v1: Deterministic teardown and startup reconciliation
- [x] v1.5: Overlay scratch disk per execution
- [x] v2: YAML policy engine
- [x] v2: aegis-cli
- [x] v2: Streaming I/O / SSE path
- [x] v2.1: Compute profiles
- [x] v2.2: Persistent workspaces
- [x] Core GitHub Actions workflow green
- [x] Allowlist DNS interception / smoke test stabilization
  - [x] Managed-child SIGCHLD gating in guest-runner
  - [x] Guest DIAG stderr is now opt-in via `AEGIS_DEBUG=1`
  - [x] Python guest invocation stabilized with `-S -u`
  - [x] Loopback initialization added in guest network setup
  - [x] 100ms post-network settle delay added before user process launch
  - [x] Guest resolver timeout increased to `timeout:5 attempts:2`
  - [x] Host-side per-VM DNS interceptor resolves allowlisted hosts and denies non-allowlisted hosts
  - [x] DNS interceptor now handles packets synchronously for the single-VM path
  - [x] `tests/integration/allowlist_dns.sh` passes repeatedly with `timeout_ms: 25000`
- [x] Phase 2 validation coverage
  - [x] `tests/integration/smoke.sh` covers health, execute, timeout, concurrency/429, teardown, allowlist resolve, and allowlist deny
  - [x] `tests/integration/abuse.sh` covers fork bomb, infinite loop, memory bomb, huge stdout truncation, process explosion, and post-abuse health
  - [x] `.github/workflows/ci.yml` runs both validation scripts on the GitHub Actions Linux runner
- [x] Phase 3 observability
  - [x] `/ready` returns readiness based on DB connectivity and worker-slot availability
  - [x] `/metrics` exports Prometheus-style execution, boot, teardown, and worker-slot metrics
  - [x] orchestrator and executor hot paths now emit structured JSON logs

- [x] Phase 4 install simplicity
  - [x] scripts/preflight.sh checks Linux, KVM, Firecracker, assets, cgroup v2, iptables, and Postgres reachability
  - [x] scripts/install.sh is idempotent enough to rerun safely in local setup
  - [x] scripts/smoke-local.sh provides a one-command local doctor path and can reuse an existing healthy orchestrator
- [x] Phase 5 documentation
  - [x] THREAT_MODEL.md documents the security boundary and explicit non-goals
  - [x] KNOWN_LIMITATIONS.md documents current runtime and platform caveats
  - [x] README.md now links to both docs, includes the architecture diagram, and documents install/demo/validation entry points

## In Progress
- [ ] Crunch profile validation follow-up
- [ ] Workspace durability cleanup
- [ ] Observability cleanup

## Up Next

### 1. Crunch profile validation follow-up
- [ ] Re-test `crunch` with a higher timeout on WSL2 and Linux CI
- [ ] Decide whether `crunch` needs a timeout recommendation or CI exception
- [ ] Add a stronger kernel-level memory pressure test if hard OOM proof is required

### 2. Workspace durability cleanup
- [ ] Investigate why the second successful workspace read still reports `exit_code: 1`
- [ ] Decide whether this is guest-runner cleanup noise or a shell-level nonzero exit worth surfacing differently

### 3. Observability cleanup
- [ ] Remove temporary DNS packet hex logging from the interceptor now that Phase 3 metrics/logging are in place
- [ ] Consider adding execution-status metrics for stream handler early-error paths if parity with `/v1/execute` becomes important

### 4. Validation maintenance
- [ ] Keep `tests/integration/smoke.sh` and `tests/integration/abuse.sh` aligned with runtime behavior as executor limits evolve

## Deferred
- Node.js on WSL2 remains sensitive to guest entropy/runtime behavior
- Full vsock HTTP proxy for package installs
- Filesystem jail inside guest
- GitHub IAM proxy
- Firecracker snapshots

## Notes
- The core product is beyond toy stage: real microVMs, audited execution, cgroup enforcement, deterministic teardown, and a policy surface all work
- Host-side enforcement remains the source of truth for isolation
- Compute profiles and persistent workspaces are useful platform hardening, not architectural experiments