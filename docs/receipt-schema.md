# Receipt Schema

This document is the public field guide for current Aegis receipts. For the raw contract, use [../schemas/receipt-predicate-v1.json](../schemas/receipt-predicate-v1.json).

## Signed Envelope

Aegis signs an in-toto Statement v1 inside a DSSE envelope:

- `_type=https://in-toto.io/Statement/v1`
- `predicateType=https://aegis.dev/ExecutionReceipt/v1`
- `predicate.version=v1`

The signed statement binds:

- `subject[]` artifact hashes
- the Aegis predicate

Typical proof bundle files:

- `receipt.dsse.json`
- `receipt.pub`
- `receipt.summary.txt`
- `output-manifest.json`
- captured stdout/stderr artifacts when present

`receipt.summary.txt` is convenience output only. It is not the signed source of truth.

## Current Receipt Semantics

Current receipts carry a receipt-level semantics marker.

- legacy receipts: older semantics that the verifier still accepts for backward compatibility
- current receipts: current runtime semantics, including lease-covered action requirements

For current semantics receipts, covered allow-path actions must include lease evidence.

Current covered allow-path actions:

- `http_request`
- `host_repo_apply_patch`

## Core Predicate Areas

### Execution identity and outcome

The predicate includes fields such as:

- `execution_id`
- timing fields
- status / outcome / exit code
- denial markers when present

### Authority envelope

Current authority evidence includes:

- `policy_digest`
- `authority_digest`
- `broker_action_types`
- `broker_repo_labels`

Only repo labels are signed. Absolute host repo roots are intentionally not part of signed authority evidence.

### Lease evidence

Raw governed actions can carry lease evidence:

- `lease_id`
- `issuer`
- `issuer_key_id`
- `result`
- `reason`
- `expires_at`
- `grant_id`
- `selector_digest`
- `selector_digest_algo`
- `budget_result`
- `remaining_count`

Current covered allow-path receipts require valid lease evidence.

### Approval evidence

Raw governed actions can carry approval evidence:

- `required`
- `ticket_id`
- `issuer_key_id`
- `result`
- `reason`
- `expires_at`
- `resource_digest`
- `resource_digest_algo`
- `consumed`

Approval remains separate from leases.

### Host-action evidence

`host_repo_apply_patch` actions can carry typed host-action evidence:

- `host_action.class`
- `repo_label`
- `target_scope`
- `affected_paths`
- `patch_digest`
- `patch_digest_algo`
- `base_revision`

Receipts intentionally do not sign absolute host repo roots.

### Escalation evidence

Denied governed actions can carry escalation signals:

- `authority_broadening_attempt`
- `destructive_boundary_probe`
- `unsupported_destructive_class_access`
- `repeated_probing_pattern`

Execution-level runtime policy summary can carry:

- `runtime.policy.escalation_attempts`
- `runtime.policy.denied_destructive_actions`
- `runtime.policy.termination_reason`

## What Verification Checks

`aegis receipt verify --proof-dir ...` checks:

- DSSE signature validity
- artifact hashes against `subject[]`
- schema shape
- current semantic invariants
- summary consistency rules

Examples of enforced current invariants:

- covered allow-path actions require lease evidence under current receipt semantics
- contradictory approval or lease states fail verification
- malformed escalation summaries fail verification
- unknown enum values fail verification

## Human-Oriented Output

Current `receipt show` / `receipt verify` output surfaces key fields including:

- `authority_digest`
- `broker_action_types`
- `broker_repo_labels`
- `lease_id`
- `lease_result`
- `lease_budget_result`
- `approval_ticket_id`
- `approval_result`
- `host_action_class`
- `repo_label`
- `patch_digest`
- `affected_paths`
- `runtime_policy_escalation_*`

Public summary output is intentionally sanitized:

- no raw approval tokens
- no raw host repo roots
- no raw HTTP query strings in human/signed audit output

## What Receipts Prove

Receipts prove that the verifier checked a host-produced signed execution record and its bound artifacts.

They do **not** prove:

- attestation
- trustlessness
- host independence
- that the host could not forge or suppress evidence
