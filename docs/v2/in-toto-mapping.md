# in-toto Mapping

Aegis v2 receipts use an in-toto Statement v1 as the signed payload and a DSSE envelope as the signing wrapper. The Aegis-specific data model is the custom predicate defined in `schemas/receipt-predicate-v1.json`.

## Statement Shape

- `subject[]`: output artifacts produced by the execution, each with a digest
- `predicateType`: `https://aegis.dev/ExecutionReceipt/v1`
- `predicate`: Aegis execution receipt predicate payload

Output artifact binding is canonical only through in-toto `subject[]`. Any predicate copy of artifacts is convenience metadata and must not be treated as the cryptographic source of truth.

## Signing Flow

1. Canonicalize and digest the intent contract.
2. Canonicalize and digest the normalized event log.
3. Build the Aegis predicate payload with verdict, summaries, violations, and optional host attestation reference.
4. Build the in-toto Statement with `subject[]`, `predicateType`, and `predicate`.
5. Sign the exact serialized Statement bytes inside a DSSE envelope.

## Verification Expectations

- Verify the DSSE envelope before parsing the Statement payload semantically.
- Use the verified payload bytes as the Statement input; do not reparse the envelope and reload payload bytes through a second path.
- Verify the signer identity against the trusted Aegis key set.
- Treat `subject[]` as the authoritative output artifact binding.
- Treat `intent_digest` and `event_log_digest` as bindings to external stored material, not as a replacement for raw evidence retention.

## Raw Event Storage vs Signed Receipt

The signed predicate records the digests, verdict, and execution summaries needed for portable verification. Raw normalized event logs may still be stored separately for investigation, replay, or operator search. Those raw logs are not the receipt itself unless their canonical digest matches `event_log_digest`.
