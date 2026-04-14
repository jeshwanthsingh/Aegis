# Trust Model

This document states plainly what Aegis does and does not prove today.

## What is in the trust base

- the Linux host running Aegis
- the host kernel, local filesystem, and local database
- the host-side Aegis control plane
- the local receipt signing seed and signer process

The host is in the trust base.

## What is not proven today

- no host attestation
- no external hardware-rooted proof that the host was honest
- no HSM or KMS custody for receipt signing keys
- no proof that a compromised host could not forge or omit evidence

## What receipts are

Receipts are signed host-side execution records.

They bind:

- an execution ID
- execution timestamps
- backend identity
- outcome and exit code
- runtime evidence digests
- artifact hashes for proof-bundle outputs
- signer key ID and signing mode
- denial details and governed-action details when present

## What a compromised host can do

A compromised host can lie.

More concretely, a compromised host could:

- forge or suppress runtime telemetry before building the receipt
- sign a false receipt with the local signing key
- replace or omit proof-bundle artifacts before you fetch them
- serve a runtime that behaves differently from the code you expected

Aegis does not solve that problem today.

## What contributes to trust anyway

Even with the host in the trust base, the current receipt still gives useful structure:

- `execution_id` ties the receipt to one run
- `started_at` and `finished_at` tie it to a concrete execution window
- `backend` states the runtime backend used
- `policy_digest` binds the canonical execution policy context for the run
- `signer_key_id` identifies which local signer produced the receipt
- `signing_mode` and `key_source` tell you whether the signer came from configured local seed material or a dev fallback
- artifact `sha256` hashes bind the proof-bundle outputs that were signed
- `intent_digest` binds the explicit execution intent when present
- governed-action `policy_digest` values still bind the exact action-specific policy scope consulted for those actions
- `denial_rule_id` and `denial_marker` explain why a direct action was denied
- `trust.limitations` tells you which known trust gaps still apply

## Current Phase 1 / Phase 2 posture

- host attestation: absent
- signing custody: local
- receipt verification material: Ed25519 public key
- trust limitation markers: present in receipts and surfaced in verification summaries

For the concrete fields, use [receipt-schema.md](receipt-schema.md).
