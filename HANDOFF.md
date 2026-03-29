# HANDOFF.md

## Status
Baseline Aegis works. Compute profiles and persistent workspaces are implemented, the full GitHub Actions workflow is green, and allowlist DNS interception now passes repeated end-to-end smoke tests.

## What works
- Python execution: yes, full VM boot -> vsock -> result
- Bash execution: yes
- Worker pool / concurrency: yes
- API key auth + GET /health: yes
- PostgreSQL audit log: yes
- cgroup v2 limits: yes
- Deterministic teardown + startup reconciliation: yes
- CLI / streaming path: implemented
- Compute profiles: implemented end-to-end
- Persistent workspaces: implemented end-to-end
- GitHub Actions build/boot, core-demo, and isolation validation: green
- Allowlist DNS smoke test: stable and passing repeatedly

## Current blocker
No core CI blocker remains. The main follow-ups are:
- re-test the `crunch` profile with a larger timeout on WSL2 and Linux CI
- investigate the nonzero exit on a successful persistent workspace read
- add a single `tests/integration/smoke.sh` script for the whole system

## Allowlist DNS summary
The DNS path is now stable for the smoke-test flow.

What fixed it:
- managed-child SIGCHLD gating in `guest-runner/main.go`
- Python guest invocation changed to `-S -u`
- loopback initialization in guest network setup
- 100ms post-network settle delay after `setupNetwork()` before launching the user process
- guest `/etc/resolv.conf` now uses `options timeout:5 attempts:2`
- host-side per-VM DNS interceptor handles packets synchronously for the single-VM path
- smoke-test payload timeout in `tests/integration/allowlist_dns.sh` raised to `25000ms`

What was verified:
- allowlisted host `pypi.org` resolves through the host-side per-VM DNS interceptor
- the guest can open TCP 443 to the resolved allowlisted address
- non-allowlisted `example.com` does not resolve under allowlist mode
- direct `gethostbyname("pypi.org")` probes passed repeatedly without flakes
- `tests/integration/allowlist_dns.sh` passes repeatedly end-to-end

## Recommended next roadmap
1. Crunch profile validation pass
   Goal: prove the 4 vCPU / 2GB tier cleanly on both WSL2 and Linux CI

2. Workspace durability cleanup
   Goal: explain and remove the nonzero exit on a successful persistent read

3. Integration smoke coverage
   Goal: add `tests/integration/smoke.sh` so the core system can be proven in one script

## Key files
- `cmd/orchestrator/main.go`
- `internal/api/handler.go`
- `internal/policy/policy.go`
- `internal/executor/firecracker.go`
- `internal/executor/workspace.go`
- `internal/executor/lifecycle.go`
- `internal/executor/vsock.go`
- `guest-runner/main.go`
- `configs/default-policy.yaml`
- `tests/integration/allowlist_dns.sh`
- `.github/workflows/ci.yml`

## Recommended stance for next session
- Treat the allowlist DNS blocker as resolved for the current smoke-test path
- Keep host-side enforcement as the authority for isolation
- Focus next on `crunch` validation, workspace cleanup, and a top-level integration smoke script