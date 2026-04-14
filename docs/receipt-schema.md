# Receipt Schema

This documents the canonical receipt fields in the current Aegis implementation.

The proof bundle produced for one execution contains:

- `receipt.dsse.json`
- `receipt.pub`
- `receipt.summary.txt`
- bound output artifacts such as `stdout.txt`, `stderr.txt`, and `output-manifest.json`

## Structure

The signed receipt is a DSSE envelope over an in-toto statement.

Current constants in implementation:

- statement `_type`: `https://in-toto.io/Statement/v1`
- envelope `payloadType`: `application/vnd.in-toto+json`
- statement `predicateType`: `https://aegis.dev/ExecutionReceipt/v1`
- predicate `version`: `v1`

## Canonical predicate fields

Current predicate fields implemented in `internal/receipt/types.go`:

- `version`
- `execution_id`
- `workflow_id`
- `backend`
- `task_class`
- `declared_purpose`
- `workspace_id`
- `execution_status`
- `semantics_mode`
- `result_class`
- `denial`
- `policy_digest`
- `intent_digest`
- `intent_digest_algo`
- `evidence_digest`
- `evidence_digest_algo`
- `runtime_event_count`
- `point_decisions`
- `divergence`
- `outcome`
- `trust`
- `limitations`
- `started_at`
- `finished_at`
- `signer_key_id`
- `broker_summary`
- `governed_actions`
- `metadata`

## Fields called out for Phase 2

### Schema version

- `predicate.version`
- current value: `v1`

### Execution ID

- `predicate.execution_id`

### Timestamps

- `predicate.started_at`
- `predicate.finished_at`

### Backend

- `predicate.backend`
- example: `firecracker`

### Policy digest

Current implementation:

- `predicate.policy_digest` is the top-level execution policy digest for the run
- current implementation derives it from the evaluated intent policy context
- governed actions still keep their own `policy_digest` when the exact consulted scope is action-specific

Related current fields:

- `predicate.policy_digest`
- `predicate.intent_digest`
- `predicate.governed_actions.actions[].policy_digest`
- `predicate.governed_actions.normalized[].policy_digest`

### Signer key ID

- `predicate.signer_key_id`
- also repeated as the DSSE signature `keyid`

### Signing mode

- `predicate.trust.signing_mode`
- current modes: `strict`, `dev`

### Outcome

- `predicate.outcome.reason`

### Exit code

- `predicate.outcome.exit_code`

### Execution status

- `predicate.execution_status`

### Denial marker

- `predicate.denial.marker`
- also repeated in governed-action entries when applicable

### Denial rule ID

- `predicate.denial.rule_id`
- also repeated in governed-action entries when applicable

### Governed actions

- `predicate.governed_actions.count`
- `predicate.governed_actions.actions[]`
- `predicate.governed_actions.normalized[]`

Governed action records currently include:

- `action_type`
- `target`
- `resource`
- `method`
- `capability_path`
- `decision`
- `outcome`
- `used`
- `reason`
- `rule_id`
- `policy_digest`
- `brokered`
- `brokered_credentials`
- `binding_name`
- `response_digest`
- `response_digest_algo`
- `denial_marker`
- `audit_payload`
- `error`

### Artifact hashes

Artifact hashes are bound through the statement `subject` list:

- `statement.subject[].name`
- `statement.subject[].digest.sha256`

The proof verifier also checks those hashes against the artifact files in the proof bundle.

### Trust limitations

Trust limits are expressed in two places:

- `predicate.trust.limitations`
- `predicate.limitations`

Current examples:

- `host_attestation_absent`
- `dev_signing_mode`
- `fallback_dev_seed`
- `host attestation deferred`
- `captured standard stream artifacts may be truncated`

## What the summary file surfaces

`receipt.summary.txt` is a verifier-friendly text projection, not the full schema.

It currently surfaces:

- `verification`
- `schema_version`
- `execution_id`
- `backend`
- `policy_digest`
- `signer_key_id`
- `intent_digest`
- `signing_mode`
- `trust_limitations`
- `semantics_mode`
- `result_class`
- `key_source`
- `attestation`
- `started_at`
- `finished_at`
- `outcome`
- `exit_code`
- `divergence_verdict`
- `rule_hits`
- `artifact_count`
- `artifacts`
- `workspace_id` when present
- `execution_status` when present
- `denial_class`, `denial_rule_id`, `denial_marker` when present
- broker and governed-action summaries when present

Current implementation gap:

- the summary still does not print a digest algorithm field for `policy_digest`
- per-governed-action `policy_digest` values remain separate from the top-level execution `policy_digest`
