# Phase 1 - Schemas First

## Goal
Lock the external contract surface for Aegis v2 before backend or enforcement work continues.

## Non-goals
- No Firecracker or gVisor runtime changes
- No event capture implementation
- No Cedar evaluator implementation
- No divergence engine logic
- No DSSE signing or verification code
- No OTel export, ML, or attestation plumbing

## Deliverables
- `schemas/intent-v1.json`
- `schemas/event-v1.json`
- `schemas/violation-v1.json`
- `schemas/receipt-predicate-v1.json`
- `docs/v2/cedar-compilation-target.md`
- `docs/v2/in-toto-mapping.md`

## Acceptance Criteria
- All four schemas use JSON Schema draft 2020-12
- Required and optional fields are explicit
- Event, verdict, severity, and backend enums match the locked v2 design
- Receipt schema defines only the custom Aegis predicate payload
- Docs explain Cedar compilation targets and in-toto subject binding without introducing new runtime scope

## Constraints
- JSON schema is the product-facing API
- Cedar remains an internal evaluation target
- Output artifacts bind canonically through in-toto `subject[]`, not the predicate
- Keep design conservative; unresolved runtime behavior stays out of scope

## Open Questions
- None for Phase 1
