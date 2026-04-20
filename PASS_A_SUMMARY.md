# PASS A Summary

## Files changed
- `README.md`: updated top-level network-mode references to the canonical `egress_allowlist` wording.
- `THREAT_MODEL.md`: removed stale `direct_web_egress` claims so the threat model matches the new two-mode surface.
- `configs/default-policy.yaml`: switched the default policy surface to `mode: none` with an explicit empty allowlist.
- `docs/receipt-model.md`: updated receipt network-mode documentation to the canonical mode set and legacy-normalization wording.
- `docs/setup-local.md`: added a short engineer-facing network-modes subsection for `none` and `egress_allowlist`.
- `docs/trust-model.md`: updated trust/runtime language to match the new network-mode story.
- `guest-runner/main.go`: only writes `/etc/resolv.conf` when the effective allowlist includes FQDNs.
- `internal/api/handler.go`: resolves the per-execution effective allowlist, rejects widening requests, and records the normalized runtime/policy network evidence.
- `internal/api/handler_test.go`: added the 400-path test for intent allowlist expansion beyond baseline.
- `internal/api/helpers_test.go`: updated receipt/runtime envelope expectations for canonical mode + allowlist fields.
- `internal/capabilities/request.go`: removed the synthetic `127.0.0.1` network-scope injection from broker compilation.
- `internal/executor/lifecycle.go`: made `egress_allowlist` the single networked enforcement path, including CIDR rules, FQDN resolution, and DNS-interceptor gating.
- `internal/executor/lifecycle_test.go`: added exact iptables sequencing and DNS-interceptor coverage for the new enforcement path.
- `internal/governance/governance.go`: mapped the new evaluator deny reasons to the direct-egress governance rule IDs.
- `internal/mcp/tools_test.go`: updated broker capability expectations after removing the synthetic loopback allowlist entry.
- `internal/policy/contract/contract.go`: repurposed `allowed_domains` / `allowed_ips` as per-execution allowlist subsets and added strict subset resolution.
- `internal/policy/contract/contract_test.go`: added allowlist subset, inheritance, rejection, and field-presence coverage.
- `internal/policy/evaluator/evaluator.go`: aligned connect-event decisions with the host firewall, including hard denies and allowlist matching.
- `internal/policy/evaluator/evaluator_extra_test.go`: updated public-IP test fixtures to match the new hard-deny baseline.
- `internal/policy/evaluator/evaluator_test.go`: updated connect semantics and added the empty-allowlist deny-all test.
- `internal/policy/policy.go`: introduced canonical mode normalization, allowlist validation, and one-time deprecated-mode warnings.
- `internal/policy/policy_test.go`: added canonical validation and deprecated-mode warning coverage.
- `internal/receipt/builder.go`: canonicalized receipt network evidence and emitted explicit allowlist data with empty `presets`.
- `internal/receipt/builder_test.go`: updated receipt expectations for canonical modes and allowlist evidence.
- `internal/receipt/testdata/legacy_direct_web_egress_receipt.json`: added a pre-change legacy receipt fixture for backward-compat verification.
- `internal/receipt/types.go`: added allowlist receipt-envelope types and kept `presets` for compatibility.
- `internal/receipt/verify.go`: normalized legacy receipt modes into `egress_allowlist` and validated the new allowlist envelope.
- `internal/receipt/verify_test.go`: added canonical-mode and legacy-fixture verification coverage.
- `schemas/receipt-predicate-v1.json`: kept the schema additive via optional `allowlist` while restricting canonical mode enums to `none` / `egress_allowlist`.
- `scripts/run-demo.sh`: corrected stale network-mode comments to match the current product truth.

## Decisions made that the prompt did not specify
- When any per-execution allowlist field is explicitly present, omitted allowlist dimensions do not inherit the baseline; only a request with no allowlist fields at all inherits the full baseline.
- Loopback destinations remain evaluator-allowed by runtime baseline so brokered loopback traffic still works after removing the synthetic `127.0.0.1` capability injection.
- The executor resolves FQDN allowlist entries once during network setup and serves DNS answers from that resolved snapshot so the firewall and DNS interceptor stay aligned.
- Receipt `presets` are preserved as empty arrays for new receipts, and the effective enforced allowlist is carried in a new optional `allowlist` sibling field.

## Deviations from the plan and why
- Added `internal/receipt/testdata/legacy_direct_web_egress_receipt.json` because acceptance criterion 7 required a pre-change receipt fixture and none existed.
- Touched `guest-runner/main.go` even though it was not listed in the touched-files block, because the prompt’s enforcement section explicitly required CIDR-only mode to skip guest DNS setup.
- Touched `THREAT_MODEL.md`, `docs/trust-model.md`, and `docs/receipt-model.md` because the acceptance grep and honesty constraints required removing stale non-test `direct_web_egress` claims.
- Touched `internal/api/helpers_test.go`, `internal/mcp/tools_test.go`, and `internal/policy/evaluator/evaluator_extra_test.go` because the refactor changed shared expectations those tests asserted.
- The orchestrator startup acceptance checks were proven with live short bring-ups against the repo’s configured local Postgres DSN instead of a dedicated orchestrator unit test, because `cmd/orchestrator/main.go` connects to Postgres before `policy.Load`.

## Additional acceptance proofs
- Legacy-mode startup proof command:

```bash
cd /home/cellardoor72/aegis && sed "s/mode: none/mode: direct_web_egress/" configs/default-policy.yaml > /tmp/aegis-legacy-policy.yaml && timeout 5s go run ./cmd/orchestrator --db "postgres://postgres:postgres@localhost/aegis?sslmode=disable" -policy /tmp/aegis-legacy-policy.yaml -addr 127.0.0.1:18081 > /tmp/aegis-legacy-startup.log 2>&1; status=$?; if [ "$status" -ne 124 ]; then cat /tmp/aegis-legacy-startup.log; exit "$status"; fi
```

- Legacy-mode startup proof output excerpt:

```text
1
{"cgroup_parent":"/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/aegis","event":"cgroup_parent_ready","level":"info","ts":"2026-04-20T03:58:27.209925443Z"}
WARN: network.mode="direct_web_egress" is deprecated; normalized to "egress_allowlist".
      Update your policy to use "egress_allowlist" explicitly.
{"event":"policy_loaded","level":"info","policy_path":"/tmp/aegis-legacy-policy.yaml","ts":"2026-04-20T03:58:27.211493234Z"}
{"event":"auth_disabled_local_only","level":"warn","listen_addr":"127.0.0.1:18081","message":"AEGIS_API_KEY not set; unauthenticated mode is allowed only on loopback bind addresses","ts":"2026-04-20T03:58:27.211498975Z"}
{"event":"ui_enabled","level":"info","ts":"2026-04-20T03:58:27.211562663Z","ui_dir":"ui"}
{"addr":"127.0.0.1:18081","cors_origins":null,"event":"server_listen","level":"info","local_only":true,"ts":"2026-04-20T03:58:27.211565899Z"}
```

- Empty-allowlist startup proof command:

```bash
cd /home/cellardoor72/aegis && sed "s/mode: none/mode: egress_allowlist/" configs/default-policy.yaml > /tmp/aegis-egress-allowlist-policy.yaml && timeout 5s go run ./cmd/orchestrator --db "postgres://postgres:postgres@localhost/aegis?sslmode=disable" -policy /tmp/aegis-egress-allowlist-policy.yaml -addr 127.0.0.1:18082 > /tmp/aegis-egress-allowlist-startup.log 2>&1; status=$?; if [ "$status" -ne 124 ]; then cat /tmp/aegis-egress-allowlist-startup.log; exit "$status"; fi
```

- Empty-allowlist startup proof output excerpt:

```text
{"cgroup_parent":"/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/aegis","event":"cgroup_parent_ready","level":"info","ts":"2026-04-20T03:58:26.704189989Z"}
{"event":"policy_loaded","level":"info","policy_path":"/tmp/aegis-egress-allowlist-policy.yaml","ts":"2026-04-20T03:58:26.713581109Z"}
{"event":"auth_disabled_local_only","level":"warn","listen_addr":"127.0.0.1:18082","message":"AEGIS_API_KEY not set; unauthenticated mode is allowed only on loopback bind addresses","ts":"2026-04-20T03:58:26.713591508Z"}
{"event":"ui_enabled","level":"info","ts":"2026-04-20T03:58:26.713655778Z","ui_dir":"ui"}
{"addr":"127.0.0.1:18082","cors_origins":null,"event":"server_listen","level":"info","local_only":true,"ts":"2026-04-20T03:58:26.713659074Z"}
```

- Empty-allowlist deny proof command:

```bash
cd /home/cellardoor72/aegis && go test ./internal/policy/evaluator -run "TestEvaluateDeniedWhenEgressAllowlistIsEmpty" -v
```

- Empty-allowlist deny proof output:

```text
=== RUN   TestEvaluateDeniedWhenEgressAllowlistIsEmpty
--- PASS: TestEvaluateDeniedWhenEgressAllowlistIsEmpty (0.00s)
PASS
ok  	aegis/internal/policy/evaluator	(cached)
```

## Exact `go test` output for the new tests
- `go test ./internal/policy -run "TestValidateAllowsEgressAllowlistWithEmptyAllowlist|TestValidateAllowsEgressAllowlistWithFQDNs|TestValidateAllowsEgressAllowlistWithCIDRs|TestValidateRejectsMalformedCIDR|TestLoadNormalizesDeprecatedModesAndWarnsOnce" -v`

```text
=== RUN   TestValidateAllowsEgressAllowlistWithEmptyAllowlist
=== PAUSE TestValidateAllowsEgressAllowlistWithEmptyAllowlist
=== RUN   TestValidateAllowsEgressAllowlistWithFQDNs
=== PAUSE TestValidateAllowsEgressAllowlistWithFQDNs
=== RUN   TestValidateAllowsEgressAllowlistWithCIDRs
=== PAUSE TestValidateAllowsEgressAllowlistWithCIDRs
=== RUN   TestValidateRejectsMalformedCIDR
=== PAUSE TestValidateRejectsMalformedCIDR
=== RUN   TestLoadNormalizesDeprecatedModesAndWarnsOnce
=== RUN   TestLoadNormalizesDeprecatedModesAndWarnsOnce/isolated
=== RUN   TestLoadNormalizesDeprecatedModesAndWarnsOnce/direct_web_egress
=== RUN   TestLoadNormalizesDeprecatedModesAndWarnsOnce/allowlist
--- PASS: TestLoadNormalizesDeprecatedModesAndWarnsOnce (0.00s)
    --- PASS: TestLoadNormalizesDeprecatedModesAndWarnsOnce/isolated (0.00s)
    --- PASS: TestLoadNormalizesDeprecatedModesAndWarnsOnce/direct_web_egress (0.00s)
    --- PASS: TestLoadNormalizesDeprecatedModesAndWarnsOnce/allowlist (0.00s)
=== CONT  TestValidateAllowsEgressAllowlistWithEmptyAllowlist
--- PASS: TestValidateAllowsEgressAllowlistWithEmptyAllowlist (0.00s)
=== CONT  TestValidateAllowsEgressAllowlistWithFQDNs
--- PASS: TestValidateAllowsEgressAllowlistWithFQDNs (0.00s)
=== CONT  TestValidateAllowsEgressAllowlistWithCIDRs
=== CONT  TestValidateRejectsMalformedCIDR
--- PASS: TestValidateRejectsMalformedCIDR (0.00s)
--- PASS: TestValidateAllowsEgressAllowlistWithCIDRs (0.00s)
PASS
ok  	aegis/internal/policy	0.002s
```

- `go test ./internal/policy/contract -run "TestResolveEffectiveAllowlist|TestLoadIntentContractJSONTracksAllowlistFieldPresence" -v`

```text
=== RUN   TestResolveEffectiveAllowlist
=== PAUSE TestResolveEffectiveAllowlist
=== RUN   TestLoadIntentContractJSONTracksAllowlistFieldPresence
=== PAUSE TestLoadIntentContractJSONTracksAllowlistFieldPresence
=== CONT  TestResolveEffectiveAllowlist
=== RUN   TestResolveEffectiveAllowlist/equal_baseline_accepted
=== RUN   TestResolveEffectiveAllowlist/strict_subset_accepted
=== RUN   TestResolveEffectiveAllowlist/fqdn_not_in_baseline_rejected
=== RUN   TestResolveEffectiveAllowlist/cidr_not_contained_rejected
=== RUN   TestResolveEffectiveAllowlist/exact_cidr_accepted
=== RUN   TestResolveEffectiveAllowlist/no_allowlist_fields_inherits_baseline
=== RUN   TestResolveEffectiveAllowlist/explicit_empty_arrays_yields_empty
--- PASS: TestResolveEffectiveAllowlist (0.00s)
    --- PASS: TestResolveEffectiveAllowlist/equal_baseline_accepted (0.00s)
    --- PASS: TestResolveEffectiveAllowlist/strict_subset_accepted (0.00s)
    --- PASS: TestResolveEffectiveAllowlist/fqdn_not_in_baseline_rejected (0.00s)
    --- PASS: TestResolveEffectiveAllowlist/cidr_not_contained_rejected (0.00s)
    --- PASS: TestResolveEffectiveAllowlist/exact_cidr_accepted (0.00s)
    --- PASS: TestResolveEffectiveAllowlist/no_allowlist_fields_inherits_baseline (0.00s)
    --- PASS: TestResolveEffectiveAllowlist/explicit_empty_arrays_yields_empty (0.00s)
=== CONT  TestLoadIntentContractJSONTracksAllowlistFieldPresence
--- PASS: TestLoadIntentContractJSONTracksAllowlistFieldPresence (0.00s)
PASS
ok  	aegis/internal/policy/contract	0.002s
```

- `go test ./internal/executor -run "TestSetupNetworkProgramsExpectedRules|TestSetupNetworkStartsDNSOnlyWhenFQDNsPresent" -v`

```text
=== RUN   TestSetupNetworkProgramsExpectedRules
--- PASS: TestSetupNetworkProgramsExpectedRules (0.00s)
=== RUN   TestSetupNetworkStartsDNSOnlyWhenFQDNsPresent
=== RUN   TestSetupNetworkStartsDNSOnlyWhenFQDNsPresent/fqdn_only
=== RUN   TestSetupNetworkStartsDNSOnlyWhenFQDNsPresent/cidr_only
--- PASS: TestSetupNetworkStartsDNSOnlyWhenFQDNsPresent (0.00s)
    --- PASS: TestSetupNetworkStartsDNSOnlyWhenFQDNsPresent/fqdn_only (0.00s)
    --- PASS: TestSetupNetworkStartsDNSOnlyWhenFQDNsPresent/cidr_only (0.00s)
PASS
ok  	aegis/internal/executor	0.002s
```

- `go test ./internal/api -run "TestExecuteHandlerRejectsIntentAllowlistOutsideBaseline" -v`

```text
=== RUN   TestExecuteHandlerRejectsIntentAllowlistOutsideBaseline
--- PASS: TestExecuteHandlerRejectsIntentAllowlistOutsideBaseline (0.00s)
PASS
ok  	aegis/internal/api	0.002s
```

- `go test ./internal/policy/evaluator -run "TestEvaluateDeniedWhenEgressAllowlistIsEmpty" -v`

```text
=== RUN   TestEvaluateDeniedWhenEgressAllowlistIsEmpty
--- PASS: TestEvaluateDeniedWhenEgressAllowlistIsEmpty (0.00s)
PASS
ok  	aegis/internal/policy/evaluator	(cached)
```

- `go test ./internal/receipt -run "TestVerifySignedReceiptNormalizesLegacyDirectWebEgressMode|TestVerifySignedReceiptAcceptsEgressAllowlistWithEmptyAllowlist|TestVerifySignedReceiptAcceptsEgressAllowlistWithPopulatedAllowlist|TestVerifySignedReceiptFixtureLegacyDirectWebEgress" -v`

```text
=== RUN   TestVerifySignedReceiptNormalizesLegacyDirectWebEgressMode
--- PASS: TestVerifySignedReceiptNormalizesLegacyDirectWebEgressMode (0.00s)
=== RUN   TestVerifySignedReceiptAcceptsEgressAllowlistWithEmptyAllowlist
--- PASS: TestVerifySignedReceiptAcceptsEgressAllowlistWithEmptyAllowlist (0.00s)
=== RUN   TestVerifySignedReceiptAcceptsEgressAllowlistWithPopulatedAllowlist
--- PASS: TestVerifySignedReceiptAcceptsEgressAllowlistWithPopulatedAllowlist (0.00s)
=== RUN   TestVerifySignedReceiptFixtureLegacyDirectWebEgress
--- PASS: TestVerifySignedReceiptFixtureLegacyDirectWebEgress (0.00s)
PASS
ok  	aegis/internal/receipt	0.004s
```

## Exact output of the `git grep` acceptance check
- Command:

```bash
cd /home/cellardoor72/aegis && git grep -n "direct_web_egress" | grep -v _test.go | grep -v CHANGELOG | grep -v RECON_EGRESS.md | grep -v verify.go | grep -v policy.go
```

- Output:

```text
(no output)
```

- Exit status: `1` (no matches)
