## Handoff: 2026-04-08 Phase 1 - Schemas First
## Status: COMPLETE
## What shipped:
- Wrote the Phase 1 scope brief in `ai/CURRENT_PHASE.md`
- Added `schemas/intent-v1.json`
- Added `schemas/event-v1.json`
- Added `schemas/violation-v1.json`
- Added `schemas/receipt-predicate-v1.json`
- Added `docs/v2/cedar-compilation-target.md`
- Added `docs/v2/in-toto-mapping.md`
## Decisions forced (write to DECISION_LOG.md if significant):
- Kept `backend_hint` optional and constrained to `firecracker|gvisor`
- Kept output artifact binding canonical in in-toto `subject[]`; predicate copy is optional and explicitly non-canonical
- Kept sequence-state logic out of Cedar and out of the schemas beyond the event and receipt fields needed to support it later
## Remaining in phase:
- none
## Blockers:
- none
## Next prompt for Claude:
Phase 1 contracts are now frozen as JSON schemas plus Cedar and in-toto mapping notes. Phase 2 should implement Firecracker sensor MVP event capture and host ingestion against `event-v1`, while preserving sequence numbers, drop accounting, broker events, and the current non-goals around signing and attestation.
