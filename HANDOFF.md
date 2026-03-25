# HANDOFF.md

## Status
**Baseline Aegis works. Current rough edge is CI and isolated-mode validation, not the core VM execution path.**

## What works
- Python execution: yes, full VM boot -> vsock -> result
- Bash execution: yes
- Worker pool / concurrency: yes
- API key auth + GET /health: yes
- PostgreSQL audit log: yes
- cgroup v2 limits: yes
- Deterministic teardown + startup reconciliation: yes
- Core demo tests 1-4: passing on WSL2
- CLI / streaming path: implemented
- Install/docs/OpenClaw integration: present

## Current blocker
GitHub Actions CI and isolated-mode firewall validation are still noisy.

What is true:
- The product itself is not blocked at the basic execution layer
- The remaining churn is around proving isolation behavior cleanly on Linux runners
- Some of the recent firewall experiments mixed valid filter-table rules with invalid nat-table DROP behavior on iptables-nft

What to avoid next:
- Do not keep looping on invalid `nat PREROUTING ... -j DROP` ideas
- Do not make CI depend on flaky guest-side networking or vsock timing when the real intent is host-side isolation proof

## Recommended next roadmap
1. GitHub Actions CI — 1 day
   Goal: get a real green Linux CI run and trustworthy badge

2. Compute profiles — 2 days
   Goal: package current cgroup/policy behavior into product-facing sizing options

3. Persistent workspaces — 2 days
   Goal: let agents keep files between runs without abandoning isolation boundaries

4. DNS interception — 3 days
   Goal: replace the current allowlist/IP approach with a cleaner DNS-policy layer

## Why this roadmap is good
- CI first gives credibility and faster iteration
- Compute profiles are low-risk because they reuse the policy/cgroup foundation already in place
- Persistent workspaces make the system more useful to real agents than one-shot execution alone
- DNS interception is the right cleanup for networking once the basics are stable

## Project assessment
This is a strong project.

Why:
- It solves a real problem: separating AI-generated code execution from the host
- It is not just a demo anymore; it has a VM boundary, policy engine, audit trail, concurrency model, teardown, and operator-facing surfaces
- The architecture has a clear story: orchestrator -> Firecracker -> guest-runner -> audited result
- The remaining work is product hardening and feature deepening, which is exactly where a serious project should be at this stage

What raises it further:
- one clean green CI path on Linux
- one stable networking model
- a sharper product story around profiles, workspaces, and package/install support

## Key files to remember
- `cmd/orchestrator/main.go` — flags, startup wiring, assets-dir pathing
- `internal/api/handler.go` — request validation, VM lifecycle, audit writes
- `internal/executor/firecracker.go` — VM boot and asset resolution
- `internal/executor/lifecycle.go` — cgroups, TAP/firewall lifecycle, teardown
- `internal/executor/vsock.go` — host/guest payload transport
- `guest-runner/main.go` — in-guest execution and stream framing
- `configs/default-policy.yaml` — default policy surface
- `.github/workflows/ci.yml` — CI validation path
- `scripts/run-demo.sh` — human demo / regression script

## Recommended stance for next session
- treat CI/network validation as an infrastructure cleanup task, not as evidence that the core design is failing
- keep host-side enforcement as the authority for isolation
- prioritize shipping a narrow, correct isolated-mode proof over broad but brittle networking behavior