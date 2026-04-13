# Canonical Demo

This is the one obvious Aegis demo story.

Run:

```bash
python3 scripts/run_canonical_demo.py --serve
```

That default command proves only three things:

- an allowed governed action works
- denied direct egress is blocked
- receipt verification proves both outcomes

## Expected output shape

Expect the run to end with output shaped like this:

```text
status=passed
story=allowed_governed_action,denied_direct_egress,receipt_verification
sections=governed_action
allowed_execution_id=<uuid>
denied_execution_id=<uuid>
runtime_started_here=true|false
```

Within the case output, look for:

- `[governed_allow] ...`
- `verification=verified`
- `decision=allow`
- `[governed_deny] ...`
- `result_class=denied`
- `decision=deny`
- `denial_marker=direct_egress_denied`

## What this demo proves

- Aegis can run untrusted code in the real runtime, not a mock path.
- A policy-governed action can be allowed without turning the guest loose on raw direct egress.
- A direct outbound connect attempt can be denied.
- The proof bundle and receipt verifier confirm both outcomes after execution.

## What this demo does not prove

- hosted multi-tenant readiness
- host attestation
- HSM or KMS-backed signing custody
- universal warm-path coverage
- workspace continuity by default

## 20-second explanation

Aegis runs untrusted code inside Firecracker microVMs, lets only governed actions through the policy surface, blocks direct egress, and emits receipts you can verify afterward instead of asking you to trust logs.

## Secondary add-ons

Keep these out of the default story unless you need extra proof coverage:

- `python3 scripts/run_canonical_demo.py --serve --with-warm-path`
  Proves cold-vs-warm dispatch as a secondary performance story.
- `python3 scripts/run_canonical_demo.py --serve --with-workspace`
  Proves persistent workspace continuity as a secondary statefulness story.
- `python3 scripts/run_canonical_demo.py --serve --with-warm-path --with-workspace`
  Full Tier 2 proof-lane run for internal validation.
