# Demo Guide

These are the three packaged Aegis demo flows.

They are the only public demo path to lead with. Older manual and harness-based flows are secondary or deprecated.

These scripts make the current product story concrete without asking the user to dig through logs by hand:

- code runs inside the runtime
- unsafe direct egress can be denied on the packaged deny path
- a governed outbound path can be allowed
- each run produces a proof bundle
- each proof bundle verifies

## Before You Start

Bring the local runtime up first:

```bash
cd ~/aegis
./scripts/demo_up.sh
./scripts/demo_status.sh
```

If the runtime is healthy, the scripts below will talk to `http://127.0.0.1:8080` and write proofs under `/tmp/aegis-demo/proofs`.

These packaged demos prove specific configured paths. They do not imply that every networked execution is deny-all; for networked runs, read `policy_network_mode` and `runtime_network_mode` in the receipt summary.

## 1. Clean Execution

What it proves:

- Aegis can run code in the current runtime
- the run completes normally
- a signed receipt and proof bundle are written
- receipt verification succeeds

Run it:

```bash
./scripts/demo_clean.sh
```

Expected output shape:

```text
demo=clean_execution
stdout:
  DEMO_CLEAN_OK
execution_id=<uuid>
proof_dir=/tmp/aegis-demo/proofs/<uuid>
receipt_summary=result_class=completed outcome=completed policy_digest=<digest>
verification=verified
```

Early caveat:

- by default, `./.aegis/bin/aegis receipt verify --proof-dir ...` uses the bundle's `receipt.pub`
- that proves internal bundle integrity under that key unless you separately pin a trusted signer
- it is not host independence or hardware attestation

Receipt evidence to look for:

- `result_class=completed`
- `outcome=completed`
- `policy_digest=<non-empty digest>`
- `verification=verified`

What verification proves:

- the proof bundle artifacts hash correctly
- the DSSE receipt signature verifies
- the receipt semantics pass local verification
- the bundle is internally consistent under the receipt verification key

## 2. Exfil Denied

What it proves:

- the guest code attempted direct outbound network access
- the governed policy path denied that direct egress
- the receipt records that denial and verifies afterward

Run it:

```bash
./scripts/demo_exfil_denied.sh
```

Expected output shape:

```text
demo=exfil_denied
stdout:
  connect_ex_rc=101
  DEMO_EXFIL_ATTEMPTED
  [exit code 137]
execution_id=<uuid>
proof_dir=/tmp/aegis-demo/proofs/<uuid>
receipt_summary=result_class=denied outcome=divergence_terminated policy_digest=<digest> denial_marker=direct_egress_denied
verification=verified
```

Receipt evidence to look for:

- `result_class=denied`
- `denial_rule_id=governance.direct_egress_disabled`
- `denial_marker=direct_egress_denied`
- `verification=verified`

If you inspect the verifier output directly with the CLI, you should also see governed-action denial evidence for a `network_connect` action.

What verification proves:

- the denied execution produced a signed receipt
- the denial marker is bound into the receipt verification output
- the bundle and signature verify locally
- the denial is represented both as top-level denial evidence and as a denied governed action

Common note:

- the exact socket error text can vary, but the important signal is the verified denial path, not the specific Python socket return code

## 3. Brokered Outbound Success

What it proves:

- outbound HTTP can succeed through the governed broker path
- the governed action is recorded as allowed
- the proof bundle verifies afterward

Run it:

```bash
./scripts/demo_broker_success.sh
```

Expected output shape:

```text
demo=broker_success
stdout:
  HTTP/1.1 200 OK
  ...
  auth_present=true
  DEMO_BROKER_OK
execution_id=<uuid>
proof_dir=/tmp/aegis-demo/proofs/<uuid>
receipt_summary=result_class=completed outcome=completed policy_digest=<digest> broker_allowed_count=1
verification=verified
```

Receipt evidence to look for:

- `result_class=completed`
- `broker_allowed_count=1`
- `verification=verified`

If you inspect the verifier output directly with the CLI, you should also see governed-action allow evidence for an `http_request`.

What verification proves:

- the run completed with a signed receipt
- the governed broker path was recorded as allowed
- the bundle and signature verify locally

## Inspect A Proof Bundle Manually

Each script prints a `proof_dir`. To inspect a run manually:

```bash
./.aegis/bin/aegis receipt show --proof-dir /tmp/aegis-demo/proofs/<uuid>
./.aegis/bin/aegis receipt verify --proof-dir /tmp/aegis-demo/proofs/<uuid>
```

`receipt show` prints a sectioned review of the bundle, artifacts, execution result, governed actions, broker summary, and limitations.

`receipt verify` prints a machine-readable key=value summary and reruns bundle, signature, and semantic checks. By default, `--proof-dir` verification uses the `receipt.pub` file inside that bundle. For the trust interpretation of those results, use [Trust Model](trust-model.md) and [Receipt Model](receipt-model.md).

## Optional UI Path

The local runtime also serves the current UI at:

```text
http://127.0.0.1:8080
```

The UI uses the same backend and the same signed receipt contract. It is useful for screenshots and short demos, but the shell scripts above are the canonical demo commands.

## Stop The Demo Runtime

When you are done:

```bash
./scripts/demo_down.sh
```
