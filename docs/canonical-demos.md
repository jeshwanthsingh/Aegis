# Canonical Aegis Demos

These demos exercise the current Aegis truth boundary:

- Runtime + Verify
- signed receipts and proof bundles
- brokered HTTP
- `host_repo_apply_patch`
- approval tickets
- Lease V1
- escalation evidence and terminal escalation classes

They do **not** claim authority completeness, attestation, or trustlessness.

## Prerequisites

- Linux host
- `/dev/kvm`
- Firecracker installed
- local Postgres server binaries (`initdb`, `pg_ctl`, `psql`)
- repo-local setup completed through `aegis setup`
- local runtime assets and config
- explicit approval verifier configuration for approval-requiring demos

Run the visible demo preflight before starting the runtime or any canonical demo:

```bash
python3 ./scripts/aegis_demo.py preflight
```

The canonical demo entry points fail early if preflight does not pass. This repo is not clone-and-run yet; the preflight makes the required local bootstrap state explicit.

Start the demo runtime:

```bash
./scripts/demo_up.sh
```

The demo state lives under `/tmp/aegis-demo`:

- proofs: `/tmp/aegis-demo/proofs/<execution_id>/`
- demo artifacts: `/tmp/aegis-demo/artifacts/<demo>/<execution_id>/`
- runtime log: `/tmp/aegis-demo/orchestrator.log`

You can preview the frozen digests and broker authority before issuing approvals:

```bash
./.aegis/bin/aegis demo prepare --file path/to/intent.json
```

## Canonical Demos

Demo A, escalation termination:

```bash
./scripts/demo_escalation_termination.sh
```

Proves:

- repeated probing is denied
- escalation evidence is signed into the receipt
- execution terminates with `privilege_escalation_attempt`

Demo B, host patch denied:

```bash
./scripts/demo_host_patch_denied.sh
```

Proves:

- `host_repo_apply_patch` is lease-covered
- the action is denied without a valid approval ticket
- the receipt shows host action + approval failure truth

Demo C, host patch approved:

```bash
./scripts/demo_host_patch_approved.sh
```

Proves:

- `host_repo_apply_patch` succeeds with valid lease + valid approval
- the patch applies exactly once
- the receipt shows host action + approval + lease truth
- the host patch path is mediated by the typed broker path, not a demo-only shortcut

Demo D, brokered HTTP:

```bash
./scripts/demo_broker_http.sh
```

Proves:

- brokered HTTP succeeds with valid lease + valid approval
- the receipt shows the authority/lease/approval story without raw JSON inspection

Run the full suite:

```bash
python3 ./scripts/aegis_demo.py canonical-suite
```

## Receipt Verification

Each demo prints:

- `execution_id`
- `proof_dir`
- `verify_command`
- `receipt_summary_key_fields`

You can rerun the exact verifier command from the demo output, for example:

```bash
/home/cellardoor72/aegis/.aegis/bin/aegis receipt verify --proof-dir /tmp/aegis-demo/proofs/<execution_id>
```

For the sectioned review view:

```bash
/home/cellardoor72/aegis/.aegis/bin/aegis receipt show --proof-dir /tmp/aegis-demo/proofs/<execution_id>
```

## Approval Ticket Flow

The demo harness issues tickets locally with `aegis approval issue ...`.

Relevant envs:

- `AEGIS_APPROVAL_SIGNING_SEED_B64`: local Ed25519 private seed used to sign approval tickets
- `AEGIS_APPROVAL_PUBLIC_KEYS_JSON`: explicit runtime verifier key map

Runtime approval verification requires explicit verifier public-key configuration. The demo harness derives a local single-key map from `AEGIS_APPROVAL_SIGNING_SEED_B64` with:

```bash
/home/cellardoor72/aegis/.aegis/bin/aegis approval public-keys
```

The corresponding `public_keys_json=...` value is then passed to the runtime as `AEGIS_APPROVAL_PUBLIC_KEYS_JSON`. Tickets signed with a different seed will be rejected by the broker unless the runtime verifier key map is updated to match.

You can inspect a ticket without consuming it:

```bash
./.aegis/bin/aegis approval inspect --token <approval_token>
```

## Trust Limits

- Admission preview computes the same frozen digests used at runtime, but it is not attestation.
- Host repo labels are signed into authority; host repo roots are not.
- Demo artifacts intentionally avoid storing raw approval ticket tokens or signing seeds, and the canonical approved demos inject approval tokens in-memory instead of durable runtime staging files.
- `host_repo_apply_patch` uses a local-host advisory lock. The truthful operating assumption is a dedicated or quiesced repo during the demo.
