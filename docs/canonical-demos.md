# Canonical Demos

This is the one public demo guide for Aegis.

These demos exercise the current Aegis truth boundary:

- Runtime + Verify
- brokered HTTP
- typed `host_repo_apply_patch`
- approval tickets
- Lease V1
- host-signed receipts plus offline verification

They do not claim authority completeness, attestation, or trustlessness.

## Before You Start

Run preflight and start the runtime once:

```bash
python3 ./scripts/aegis_demo.py preflight
./scripts/demo_up.sh
```

If preflight fails, stop here and use [setup-local.md](setup-local.md).

The demo runtime uses:

- proofs: `/tmp/aegis-demo/proofs/<execution_id>/`
- demo artifacts: `/tmp/aegis-demo/artifacts/<demo>/<execution_id>/`
- runtime log: `/tmp/aegis-demo/orchestrator.log`
- demo host repo: `/tmp/aegis-demo/host-repos/demo-repo`

## Recommended First Demo

Start with the governed HTTP success path:

```bash
python3 ./scripts/aegis_demo.py broker-http
```

That is the cleanest first proof loop: governed allow, signed receipt, offline verification.

## The Four Canonical Demos

| Demo | Command | Approval needed | What it proves | Side effects |
| --- | --- | --- | --- | --- |
| Demo A: escalation termination | `python3 ./scripts/aegis_demo.py escalation-termination` | No | Repeated broker probing becomes signed terminal escalation evidence with `privilege_escalation_attempt`. | No host mutation. |
| Demo B: host patch denied | `python3 ./scripts/aegis_demo.py host-patch-denied` | No ticket is issued on purpose | `host_repo_apply_patch` is lease-covered and denied without a valid approval ticket. | No host mutation. |
| Demo C: host patch approved | `python3 ./scripts/aegis_demo.py host-patch-approved` | Yes, auto-issued by the harness | The typed host patch path succeeds once with valid lease + approval and is recorded in the receipt. | Modifies `/tmp/aegis-demo/host-repos/demo-repo/demo.txt` only. |
| Demo D: brokered HTTP | `python3 ./scripts/aegis_demo.py broker-http` | Yes, auto-issued by the harness | Brokered HTTP succeeds with valid lease + approval and is recorded as governed allow evidence. | Uses a local loopback probe only. |

Run the full suite if you want all four in order:

```bash
python3 ./scripts/aegis_demo.py canonical-suite
```

## When Approval Is Needed

- Demo A does not need approval.
- Demo B intentionally proves denial without approval.
- Demo C auto-issues a local approval ticket for the exact `host_repo_apply_patch` request.
- Demo D auto-issues a local approval ticket for the exact HTTP request.

Under the hood, the approved demos preview the exact request first:

```bash
./.aegis/bin/aegis demo prepare --config .aegis/config.yaml --lang python --file path/to/code.py --intent-file path/to/intent.json --timeout 10000
```

Then they issue the matching approval locally with `aegis approval issue ...`.

You only need to issue approvals manually if you are reproducing the demo logic without the helper script.

## How To Verify A Receipt

Each demo prints:

- `execution_id`
- `proof_dir`
- `verify_command`

Rerun the exact `verify_command` line from the demo output.

Generic form:

```bash
./.aegis/bin/aegis receipt verify --proof-dir /tmp/aegis-demo/proofs/<execution_id>
./.aegis/bin/aegis receipt show --proof-dir /tmp/aegis-demo/proofs/<execution_id>
```

`receipt verify` is the machine-readable proof check. `receipt show` is the human review view.

## What The Demos Prove

The canonical demo set proves that the current runtime can:

- run untrusted code inside Firecracker/KVM microVMs
- freeze authority before execution
- govern the current host-side side-effect paths
- require exact approvals where configured
- leave a signed proof bundle you can re-check offline

The demos do not prove:

- hardware attestation
- trustlessness
- host independence
- arbitrary shared-repo safety for host patching

## Environment Dependencies

These demos depend on the exact setup checked by:

```bash
python3 ./scripts/aegis_demo.py preflight
```

That includes:

- Linux
- `/dev/kvm`
- Firecracker
- PostgreSQL server binaries
- Go
- Python 3
- repo-local `.aegis/` state
- the kernel and rootfs assets

## Stop The Runtime

```bash
./scripts/demo_down.sh
```
