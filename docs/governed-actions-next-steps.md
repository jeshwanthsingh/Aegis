# Governed Actions Next Steps

This note exists to keep the post-v1 follow-up work attached to the repo.

## Intentionally Deferred In Governed Actions v1

- No external policy engine. The v1 seam is internal and code-native on purpose.
- No workspace headline work. Governed actions v1 focuses on external-action governance, not stateful task flow.
- No warm-pool expansion. Warm behavior remains whatever the current execution path already supports.
- No stronger signer/attestation story. Receipts remain host-signed without hardware attestation.
- No SDK or MCP redesign. Thin wrappers stay thin.
- No package-manager-specific helpers. `dependency_fetch` is typed and policy-checked, but not yet lifted into `pip` / `npm` convenience flows.

## Immediate Follow-Up Risks

- The live broker-through-guest path still needs tighter integration coverage. Unit coverage is good, but the guest proxy path deserves a dedicated end-to-end harness.
- Governed action evidence is now present in receipts, but there is still no stronger provenance for the host-side broker decision beyond host trust.
- Direct egress denial is surfaced as governed evidence for HTTP-like ports, not as a generalized external-action taxonomy.

## Likely Next Feature Candidates

- Workspace flows v1
  Stateful create/use/delete workspace execution is still the biggest product step after single-shot governed execution.

- Warm pool v2 / broader coverage
  Warm reuse should stay secondary until workspace and governed paths are both stable, but broader shape coverage is the next performance lever.

- Receipt / provenance hardening
  Add stronger host-to-receipt provenance, clearer policy digests, and eventually a stronger signer story.

- Operator doctor / self-test
  The local runtime is much healthier now, but a sharper self-test path would make future regressions cheaper to isolate.

- Identity / handshake / stronger signer story
  The broker and receipt path still trust host-local configuration more than ideal.

- Broader integration / fault coverage
  Add a small end-to-end matrix for broker allow, broker deny, direct egress deny, transient upstream failure, and receipt verification.
