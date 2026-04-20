# PASS B Summary

Superseded for the final demo narrative by `PASS_B_DEMO_RUN.md` and `PASS_B_FINALIZATION.md`.
This file captures the earlier one-execution attempt and pre-fix host diagnostics, not the final canonical two-execution Pass B demo.

## Files changed
- `PASS_B_PRECHECK.md`: recorded the pre-work gate checks confirming existing telemetry coverage and receipt-builder access to drained telemetry events.
- `internal/receipt/types.go`: added the additive `runtime.network.blocked_egress` receipt types.
- `internal/receipt/builder.go`: summarized blocked connect and denied DNS telemetry into a deterministic receipt field.
- `internal/receipt/builder_test.go`: added zero/one/repeated/overflow/mixed blocked-egress coverage.
- `internal/receipt/verify.go`: validated the new blocked-egress envelope while keeping pre-Pass-B receipts valid.
- `internal/receipt/verify_test.go`: added verification coverage for receipts containing blocked-egress data.
- `schemas/receipt-predicate-v1.json`: extended the predicate schema additively with optional `runtime.network.blocked_egress`.
- `scripts/demo_egress_allowlist.sh`: added the thin canonical demo wrapper.
- `scripts/run_egress_allowlist_demo.py`: added the canonical Pass B demo body, runtime-policy pinning, offline verification, external schema validation, JSON summary output, and fail-fast host preflights.

## Decisions made that the prompt did not specify
- `blocked_egress` counts only denied `policy.point.decision` `net.connect` events and denied `dns.query` events. I did not count denied `governed.action.v1` events, because that would double-count the same blocked direct-connect attempt.
- Hard-denied IPs are normalized to range targets in the receipt sample: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `169.254.169.254/32`.
- The positive-control beat uses a brokered request to `https://api.github.com/zen` with `broker_scope.allowed_domains=["api.github.com"]` and no credential delegation. That keeps the beat deterministic and avoids injecting a synthetic `Authorization` header into GitHub.
- The demo reuses a running orchestrator only when a policy-hash marker proves it was started with the canonical Pass B allowlist policy. Otherwise it restarts the local demo runtime under that policy.

## Deviations from the plan and why
- I kept `PASS_B_PRECHECK.md` instead of deleting or merging it because the prompt’s output block listed it as a deliverable even though the work-process block suggested removing it after work began.
- I added a host-privilege preflight to `scripts/run_egress_allowlist_demo.py` after the first real run failed at `ip tuntap add ... Operation not permitted`. Without that check, the canonical demo would fail late and noisily on hosts that cannot create TAP/iptables state.
- I could not complete the acceptance items that require a real networked execution on this host because `/home/cellardoor72/aegis/.aegis/bin/orchestrator` lacks `cap_net_admin`, the current user is not root, and `sudo -n true` requires a password. I did not attempt to add privileges in code because that is host setup, not product behavior.
- I generated one fresh post-Pass-B clean receipt under the default non-network demo runtime and validated it with the external `jsonschema` CLI. That does not replace the blocked end-to-end networked demo acceptance, but it does prove the additive schema change against a real newly produced receipt.

## Additional acceptance proofs
- Full build:

```bash
cd /home/cellardoor72/aegis && go build ./...
cd /home/cellardoor72/aegis/guest-runner && go build ./...
```

- Full tests:

```bash
cd /home/cellardoor72/aegis && go test ./cmd/... ./internal/...
cd /home/cellardoor72/aegis/guest-runner && go test ./...
```

- Vet:

```bash
cd /home/cellardoor72/aegis && go vet ./...
```

- External schema validation command used after producing a fresh clean receipt and against the legacy fixture:

```bash
python3 - <<'PY'
import json, subprocess, tempfile, pathlib
repo = pathlib.Path('/home/cellardoor72/aegis')
schema = repo / 'schemas' / 'receipt-predicate-v1.json'
receipts = {
    'new_clean': pathlib.Path('/tmp/aegis-demo/proofs/17108e27-6dfd-4574-93af-d477f2eb97ae/receipt.dsse.json'),
    'legacy_fixture': repo / 'internal' / 'receipt' / 'testdata' / 'legacy_direct_web_egress_receipt.json',
}
for label, path in receipts.items():
    doc = json.loads(path.read_text())
    pred = doc['statement']['predicate']
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as handle:
        json.dump(pred, handle)
        instance = handle.name
    proc = subprocess.run(['jsonschema', '-i', instance, str(schema)], text=True, capture_output=True)
    print(f'{label}: returncode={proc.returncode}')
    if proc.stdout:
        print(proc.stdout.rstrip())
    if proc.stderr:
        print(proc.stderr.rstrip())
    pathlib.Path(instance).unlink()
PY
```

- External schema validation output:

```text
new_clean: returncode=0
legacy_fixture: returncode=0
```

- Host-privilege probe commands proving the demo blocker:

```bash
getcap /home/cellardoor72/aegis/.aegis/bin/orchestrator /home/cellardoor72/aegis/.aegis/bin/aegis 2>/dev/null
id && groups
sudo -n true
```

- Host-privilege probe output:

```text
uid=1000(cellardoor72) gid=1000(cellardoor72) groups=1000(cellardoor72),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),114(lpadmin)
cellardoor72 adm cdrom sudo dip plugdev users lpadmin
sudo: a password is required
```

## Exact `go test` output for the new tests
- `go test ./internal/receipt -run 'TestBuildPredicateBlockedEgressZeroAttempts|TestBuildPredicateBlockedEgressOneAttempt|TestBuildPredicateBlockedEgressRepeatedTarget|TestBuildPredicateBlockedEgressTruncatesAfterTenUniqueTargets|TestBuildPredicateBlockedEgressMixedKinds|TestVerifySignedReceiptAcceptsBlockedEgressSummary|TestVerifySignedReceiptFixtureLegacyDirectWebEgress|TestReceiptPredicateMatchesSchema|TestLegacyDirectWebEgressFixturePredicateMatchesSchema' -v`

```text
=== RUN   TestBuildPredicateBlockedEgressZeroAttempts
--- PASS: TestBuildPredicateBlockedEgressZeroAttempts (0.00s)
=== RUN   TestBuildPredicateBlockedEgressOneAttempt
--- PASS: TestBuildPredicateBlockedEgressOneAttempt (0.00s)
=== RUN   TestBuildPredicateBlockedEgressRepeatedTarget
--- PASS: TestBuildPredicateBlockedEgressRepeatedTarget (0.00s)
=== RUN   TestBuildPredicateBlockedEgressTruncatesAfterTenUniqueTargets
--- PASS: TestBuildPredicateBlockedEgressTruncatesAfterTenUniqueTargets (0.00s)
=== RUN   TestBuildPredicateBlockedEgressMixedKinds
--- PASS: TestBuildPredicateBlockedEgressMixedKinds (0.00s)
=== RUN   TestReceiptPredicateMatchesSchema
--- PASS: TestReceiptPredicateMatchesSchema (0.00s)
=== RUN   TestReceiptPredicateMatchesSchemaWithDirectWebEgressMode
--- PASS: TestReceiptPredicateMatchesSchemaWithDirectWebEgressMode (0.00s)
=== RUN   TestLegacyDirectWebEgressFixturePredicateMatchesSchema
--- PASS: TestLegacyDirectWebEgressFixturePredicateMatchesSchema (0.00s)
=== RUN   TestVerifySignedReceiptAcceptsBlockedEgressSummary
--- PASS: TestVerifySignedReceiptAcceptsBlockedEgressSummary (0.00s)
=== RUN   TestVerifySignedReceiptFixtureLegacyDirectWebEgress
--- PASS: TestVerifySignedReceiptFixtureLegacyDirectWebEgress (0.00s)
PASS
ok  	aegis/internal/receipt	(cached)
```

## Captured full run of the demo output
- `cd /home/cellardoor72/aegis && ./scripts/demo_egress_allowlist.sh`

```text
Aegis egress_allowlist demo
watch_for=three blocked beats (public IP, denied DNS, RFC1918) plus one brokered allow to api.github.com with offline receipt verification
summary_json=/home/cellardoor72/aegis/scripts/demo_output/egress_allowlist/run_20260420T052153Z.json
host_check=api.github.com:443 reachable
FAIL: /home/cellardoor72/aegis/.aegis/bin/orchestrator lacks cap_net_admin and this demo is not running as root; rerun setup with elevated privileges before recording the networked demo
summary_json=/home/cellardoor72/aegis/scripts/demo_output/egress_allowlist/run_20260420T052153Z.json
```

## Acceptance status
- Acceptance items `1`, `2`, `3`, and `6` are green on this host.
- Acceptance items `4`, `5`, `7`, and `8` remain unverified on this host because a networked execution cannot start without host `cap_net_admin` (or root) for TAP and iptables setup.
