# PASS B Demo Run

## Commands run

```bash
cd /home/cellardoor72/aegis && ./scripts/demo_egress_allowlist.sh
cd /home/cellardoor72/aegis && go test ./internal/receipt -run 'TestBuildPredicateBlockedEgressZeroAttempts|TestBuildPredicateBlockedEgressOneAttempt|TestBuildPredicateBlockedEgressRepeatedTarget|TestBuildPredicateBlockedEgressTruncatesAfterTenUniqueTargets|TestBuildPredicateBlockedEgressMixedKinds|TestVerifySignedReceiptAcceptsBlockedEgressSummary|TestVerifySignedReceiptFixtureLegacyDirectWebEgress|TestReceiptPredicateMatchesSchema|TestLegacyDirectWebEgressFixturePredicateMatchesSchema'
```

## Demo summary artifact

- `summary_json=/home/cellardoor72/aegis/scripts/demo_output/egress_allowlist/run_20260420T194238Z.json`

## Phase results

### Phase A: adversarial

- `execution_id=7bbcb480-3819-4ee9-9f46-9250b48618be`
- `proof_dir=/tmp/aegis-demo/proofs/7bbcb480-3819-4ee9-9f46-9250b48618be`
- `result=terminated_as_expected`
- `exit_reason=divergence_terminated`
- `receipt_outcome=denied`
- `blocked_egress_kinds=ip,fqdn,rfc1918`
- `blocked_egress_total=4 unique=3`
- `triggered_rules=network.denied_repeated`
- `verification=verified`

### Phase B: brokered

- `execution_id=390b0f46-d788-4f49-aa9d-6f57d89041d0`
- `proof_dir=/tmp/aegis-demo/proofs/390b0f46-d788-4f49-aa9d-6f57d89041d0`
- `result=completed`
- `exit_reason=completed`
- `receipt_outcome=completed`
- `broker_allowed_count=1`
- `broker_domains_allowed=api.github.com`
- `verification=verified`

## Overall

- The proof command for the end-to-end Pass B demo is `cd /home/cellardoor72/aegis && ./scripts/demo_egress_allowlist.sh`.
- That command exited `0` and printed `overall=pass`.
- The blocked-egress receipt-focused regression command exited `0` and printed `ok  	aegis/internal/receipt	0.008s`.
- `security_defaults_weakened=false` is recorded in the summary JSON.
- No divergence thresholds, security defaults, receipt schema fields, or broker semantics were weakened for this run.
