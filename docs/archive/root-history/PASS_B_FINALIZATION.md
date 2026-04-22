# PASS B Finalization

## Files changed

- `scripts/run_egress_allowlist_demo.py`: replaced the single overloaded execution with two phase specs executed under one top-level run, added phase-specific receipt assertions, and wrote a combined summary JSON.
- `PASS_B_DEMO_RUN.md`: recorded the exact validation commands, proof directories, and key result lines from the successful Pass B run.
- `PASS_B_FINALIZATION.md`: recorded the final behavior change, rationale, and acceptance checklist.
- `PASS_B_SUMMARY.md`: added a supersession note so the earlier one-execution summary does not read as the final canonical demo state.

## Behavior change

- Before: the demo launched one execution that attempted the three deny beats and the brokered GitHub request in one payload.
- Before: the runtime correctly hit `network.denied_repeated` before the brokered beat completed, so the demo failed even though the receipt already showed the blocked-egress evidence.
- After: the top-level demo still runs as one command, but it now performs two executions.
- After: Phase A is adversarial and treats `divergence_terminated` as the intended result while proving `blocked_egress` contains `ip`, `fqdn`, and `rfc1918`.
- After: Phase B is brokered-only, completes normally, and proves the governed allow to `api.github.com`.

## Why this was the correct fix

- It matches the truth of the product: `network.denied_repeated` with threshold `2` remains intact and is now part of the intended adversarial story.
- It preserves the existing `blocked_egress` receipt schema and the narrow `api.github.com` allowlist model.
- It keeps one canonical public demo entrypoint while making the under-the-hood execution model honest.

## Silent decisions

- Added `/usr/bin` and `/tmp` to the demo intent `read_paths` so the adversarial phase terminates for the intended network reason instead of also tripping incidental `file.denied_repeated` noise from Python startup and temp-path reads.
- Kept `scripts/demo_egress_allowlist.sh` unchanged because it already provided the correct single public entrypoint.
- Reused the running demo runtime when the policy-hash marker matched the canonical Pass B policy; otherwise the existing restart-and-pin behavior still applies.

## Deviations from requested plan

- No structural deviation from the requested two-execution shape.
- I did not change `scripts/demo_egress_allowlist.sh` because the shell entrypoint already matched the requested top-level contract.

## Acceptance checklist

- PASS: top-level egress allowlist demo exits `0`.
- PASS: the top-level demo runs two executions, not one overloaded execution.
- PASS: the adversarial execution terminates as expected.
- PASS: the adversarial receipt contains `blocked_egress` with `ip`, `fqdn`, and `rfc1918`.
- PASS: the adversarial receipt verifies offline.
- PASS: the brokered execution completes normally.
- PASS: the brokered receipt shows governed allow evidence with `broker_allowed_count=1`.
- PASS: the brokered receipt verifies offline.
- PASS: no divergence thresholds or security defaults were weakened.
- PASS: the implementation is documented in `PASS_B_DEMO_RUN.md` and `PASS_B_FINALIZATION.md`.

## Commit hygiene

- No new commit was created. The Pass B work remains available for a single amend on top of `dc91f10`.
