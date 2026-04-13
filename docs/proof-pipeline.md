# Proof Pipeline v1

Proof is split into two tiers because hosted CI and real KVM containment are not the same thing.

## Tier 1: Fast PR Confidence

Workflow: `.github/workflows/ci.yml`

Runs on generic hosted `ubuntu-latest`.

What it proves:

- main-module Go unit tests still pass
- `guest-runner` unit tests still pass
- the canonical demo and red-team harness scripts still parse
- key shell entrypoints still parse

What it does not prove:

- Firecracker or `/dev/kvm` availability
- real governed execution
- warm-path behavior
- daemon-kill reconciliation
- live proof bundles from the full runtime

## Tier 2: Self-Hosted Live Proof

Workflow: `.github/workflows/proof.yml`

Runs on a self-hosted runner labeled `self-hosted`, `linux`, `x64`, `aegis-kvm`.

Trigger:

- manual `workflow_dispatch` only for now
- add automation later only after the self-hosted lane proves stable in real runs

Runner assumptions:

- Ubuntu with working `/dev/kvm`
- `systemd-run` available for delegated user scope
- `debugfs` available
- PostgreSQL 16 binaries at `/usr/lib/postgresql/16/bin`
- host asset cache present at `$HOME/aegis/assets` with `vmlinux` and `alpine-base.ext4`
- workflow materializes those cached assets into the checked-out proof workspace before the live harness runs

What it runs:

- `python3 scripts/run_canonical_demo.py --serve --with-warm-path --with-workspace`
- `python3 scripts/run_red_team_fault_matrix.py`

What it proves:

- canonical product story still works end to end
- governed allow/deny receipts still verify
- workspace continuity still works
- warm path is still live
- daemon-kill reconciliation still emits honest evidence
- warm orphan cleanup still happens on restart
- abnormal receipt verification still fails honestly

What it must not be confused with:

- Tier 1 is fast confidence only
- Tier 2 is the real proof lane
- hosted CI is not allowed to claim Tier 2 coverage

The default public-facing canonical demo is narrower than the Tier 2 proof lane. Use:

- [canonical-demo.md](canonical-demo.md) for the default product story
- `--with-warm-path` and `--with-workspace` only for secondary proof coverage
