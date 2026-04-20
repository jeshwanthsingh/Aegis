# Security FAQ

## What is Aegis?

Aegis is a single-host Firecracker/KVM runtime for running untrusted agent-generated code on a Linux host and emitting host-signed receipts afterward.

In the current implementation, that proof is a signed host-side execution record plus proof-bundle artifacts created after the run.

## What is Aegis not?

Aegis is not a hosted multi-tenant control plane, not host attestation, and not proof that a compromised host could not lie.

## What does the receipt prove?

It proves that the verifier checked a signed receipt and proof bundle produced by the local host for one execution ID.

`receipt verify` checks:

- bundle completeness
- artifact hashes against the signed subject list
- the DSSE signature
- receipt semantic invariants

By default, `receipt verify --proof-dir ...` uses the `receipt.pub` file in that proof bundle.

The receipt binds fields such as:

- execution ID
- timestamps
- backend
- policy digest
- signer key ID
- signing mode
- intent digest when present
- outcome and exit code
- denial markers and governed actions when present
- artifact hashes for the proof bundle

## What does the receipt not prove?

It does not prove that the host was honest.

It does not prove:

- host attestation
- truth independent of the host
- hardware-rooted provenance
- that a compromised host could not forge, omit, or alter local evidence before signing

## What are the host trust assumptions?

The host is in the trust base.

That includes:

- the Linux host
- the local filesystem and database
- the Aegis host-side control plane
- the local signing seed and signer process

## Why not just use a generic sandbox vendor?

For this wedge, the buyer usually needs more than "the code ran somewhere else."

- Aegis is aimed at self-hosted internal coding-agent execution
- the canonical demo shows denied direct egress, not just isolated execution
- the proof artifacts stay local to the operator's environment
- the receipt and verifier are part of the operator-visible control path

That does not make Aegis universally better than a generic sandbox vendor. It makes it a tighter fit when the requirement is self-hosted execution control for internal coding agents plus signed receipts for what the host observed and enforced.

For the full trust assumptions, use [trust-model.md](trust-model.md). For the current receipt structure and verification model, use [receipt-model.md](receipt-model.md).
