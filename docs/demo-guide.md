# Demo Guide

These are the three packaged Aegis demo flows.

They are designed to make the current product story concrete without asking the user to dig through logs by hand:

- code runs inside the runtime
- unsafe direct egress can be denied
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

Receipt evidence to look for:

- `result_class=completed`
- `outcome=completed`
- `policy_digest=<non-empty digest>`
- `verification=verified`

What verification proves:

- the proof bundle artifacts hash correctly
- the DSSE receipt signature verifies
- the receipt semantics pass local verification

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
- `denial_marker=direct_egress_denied`
- `verification=verified`

If you inspect the verifier output directly with the CLI, you should also see governed-action denial evidence for a `network_connect` action.

What verification proves:

- the denied execution produced a signed receipt
- the denial marker is bound into the receipt verification output
- the bundle and signature verify locally

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
.aegis/bin/aegis receipt show --proof-dir /tmp/aegis-demo/proofs/<uuid>
.aegis/bin/aegis receipt verify --proof-dir /tmp/aegis-demo/proofs/<uuid>
```

Use `receipt show` to read the signed summary. Use `receipt verify` to rerun bundle, signature, and semantic checks.

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
