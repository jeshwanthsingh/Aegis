# HANDOFF.md

## Status
**Baseline Aegis works. Compute profiles and persistent workspaces are now implemented. The main remaining rough edge is CI and isolated-mode validation, plus one small workspace follow-up on a spurious nonzero exit after a successful read.**

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
- GitHub Actions workflow YAML: repaired and validated locally after removing corrupted non-ASCII text
- Compute profiles: implemented end-to-end
  - `nano` verified in guest: `nproc=1`, memory ~112MB visible
  - `standard` verified in guest: `nproc=2`, memory ~490MB visible
  - invalid profile rejection verified: API returns `invalid compute profile`
  - nano memory pressure test verified userspace enforcement path: 200MB allocation returns Python `MemoryError`
- Persistent workspaces: implemented end-to-end
  - host-side reusable ext4 workspace disks under `/tmp/aegis/workspaces`
  - `workspace_id` request field wired through VM creation
  - guest-runner mounts `/dev/vdb` at `/workspace`
  - verified: write in execution 1 is readable in execution 2 from a new VM
  - verified: no `workspace_id` still behaves ephemerally
  - verified: `DELETE /v1/workspaces/{id}` removes the workspace image

## Current blocker
GitHub Actions CI and isolated-mode firewall validation still need final stabilization.

What is true:
- The product itself is not blocked at the basic execution layer
- The recent CI failures were partly workflow/test issues, not product failures
- The invalid `nat PREROUTING ... -j DROP` path has been removed from Go
- The workflow YAML now parses correctly again
- Compute profiles are real and wired into Firecracker machine-config

What remains:
- Finalize the isolated-mode CI assertion path so it checks valid host-side firewall behavior reliably
- Re-run `crunch` with a larger timeout before judging it as a product problem
- Investigate why the second successful persistent-workspace read still reports `exit_code: 1`
- If hard OOM proof is required, add a lower-level stress case than Python bytearray allocation

## Recommended next roadmap
1. GitHub Actions CI — 1 day
   Goal: get a real green Linux CI run and trustworthy badge

2. DNS interception — 3 days
   Goal: replace the current allowlist/IP approach with a cleaner DNS-policy layer

3. Crunch profile validation pass
   Goal: prove the 4 vCPU / 2GB tier cleanly on both WSL2 and Linux CI

4. Workspace durability cleanup
   Goal: explain and remove the nonzero exit on a successful persistent read

## Why this roadmap is good
- CI first gives credibility and faster iteration
- Persistent workspaces materially improve agent usefulness
- DNS interception is the right cleanup for networking once the basics are stable
- Crunch validation is now a targeted operational check, not a foundational design risk

## Project assessment
This is a strong project.

Why:
- It solves a real problem: separating AI-generated code execution from the host
- It is not just a demo anymore; it has a VM boundary, policy engine, audit trail, concurrency model, teardown, and operator-facing surfaces
- The architecture has a clear story: orchestrator -> Firecracker -> guest-runner -> audited result
- Compute profiles make it feel more like an execution platform and less like a single fixed sandbox size

## Key files to remember
- `cmd/orchestrator/main.go` — flags, startup wiring, assets-dir pathing
- `internal/api/handler.go` — request validation, compute profile selection, VM lifecycle, audit writes
- `internal/policy/policy.go` — profile definitions and default profile
- `internal/executor/firecracker.go` — VM boot, machine-config sizing, persistent-vs-ephemeral scratch selection
- `internal/executor/workspace.go` — persistent workspace disk lifecycle
- `internal/executor/lifecycle.go` — cgroups, TAP/firewall lifecycle, teardown
- `internal/executor/vsock.go` — host/guest payload transport
- `guest-runner/main.go` — in-guest execution, `/workspace` mount, and stream framing
- `configs/default-policy.yaml` — default policy surface
- `.github/workflows/ci.yml` — CI validation path
- `scripts/test-profiles.sh` — compute profile verification script
- `scripts/test-workspaces.sh` — persistent workspace verification script

## Recommended stance for next session
- treat CI/network validation as an infrastructure cleanup task, not as evidence that the core design is failing
- keep host-side enforcement as the authority for isolation
- treat compute profiles as complete feature wiring with one remaining high-end validation pass (`crunch`)