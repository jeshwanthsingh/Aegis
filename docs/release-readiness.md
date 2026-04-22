# Release Readiness

This page is the short public-push checklist for the current Aegis repo.

## Graphify Review

Phase 14 Graphify commands:

```bash
/home/cellardoor72/.local/bin/graphify update /home/cellardoor72/aegis
/home/cellardoor72/.local/bin/graphify query "Trace the admission to authority freeze to lease issue to VM start to broker to receipt path in the Aegis repo" --graph /home/cellardoor72/aegis/graphify-out/graph.json --budget 2500
/home/cellardoor72/.local/bin/graphify query "Trace the host_repo_apply_patch flow from guest entry through broker canonicalization, lease and approval checks, repo prepare/apply, and receipt evidence" --graph /home/cellardoor72/aegis/graphify-out/graph.json --budget 2500
/home/cellardoor72/.local/bin/graphify query "Trace the receipt builder and verifier path, including authority, lease, approval, host action, escalation, summary output, and proof bundle formatting" --graph /home/cellardoor72/aegis/graphify-out/graph.json --budget 2500
/home/cellardoor72/.local/bin/graphify query "Find suspicious cycles, dead packages, duplicate runtime paths, or architecture drift in the Aegis package graph" --graph /home/cellardoor72/aegis/graphify-out/graph.json --budget 2500
```

Graphify findings used in this phase:

- the admission / broker / receipt core stays structurally coherent
- the biggest release-readiness drift is documentation fragmentation, not a new architecture bug
- generated Graphify output is local analysis output and should not be committed
- the TypeScript SDK boundary needs to remain intentionally isolated from root `./...` package discovery

Source remains authoritative. Graphify output is a navigation aid, not a substitute for source review.

## Before Public Push

Run this checklist in order:

1. `git status --short` is clean
2. `./scripts/ci.sh --install-tools` is green
3. `python3 ./scripts/aegis_demo.py preflight` is green on the intended demo host
4. at least one live Firecracker/KVM canonical demo run completed on a real Linux host
5. the canonical receipt from that live run verifies with `aegis receipt verify`
6. secret scan and hygiene scan are green
7. README and the required docs set match the current runtime and demo surface

## Current Release Notes Surface

The truthful public release story today is:

- single-host Firecracker/KVM governed execution
- frozen authority plus `authority_digest`
- Lease V1 for current covered side-effect classes
- approval-ticket flow for operator-controlled exact actions
- typed `host_repo_apply_patch`
- signed receipts and offline verification
- canonical local demos for escalation, denied host patch, approved host patch, and brokered HTTP

The truthful non-claims remain:

- no attestation
- not trustless
- not a hosted multi-tenant control plane
- no claim of arbitrary busy shared-repo host patch safety
