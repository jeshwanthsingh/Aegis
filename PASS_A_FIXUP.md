# PASS A Fixup

- Restored legacy receipt-schema enum values for `policy.baseline.network.mode` and `runtime.network.mode`, with deprecation descriptions, and added schema validation coverage for the legacy fixture receipt.
- Added the explicit partial-allowlist contract subtest to pin the "omitted dimension does not inherit" behavior.
- Added the loopback-vs-public deny-all evaluator test.
- Updated runtime receipt allowlists to always record `127.0.0.0/8` when `egress_allowlist` is active, and updated receipt tests accordingly.
- Appended the requested inheritance/timing/loopback notes to `docs/setup-local.md` and matching engineer-facing notes to `THREAT_MODEL.md`.
- Added `TECH_DEBT.md` with the orchestrator boot-order note.
