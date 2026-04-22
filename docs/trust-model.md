# Trust Model

Aegis today is a single-host runtime that produces host-signed execution evidence. It raises the bar for running untrusted AI-generated code, but it does not remove trust in the host or operator.

## Short Version

- one Linux host
- Firecracker/KVM execution boundary
- host-side policy enforcement
- host-signed receipts plus offline verification
- no attestation
- not trustless

The most accurate short description is:

> Runtime + Verify on one host you already trust.

## Trust Base

The trust base currently includes:

- the Linux host and kernel
- Firecracker, guest kernel, rootfs, and host-side runtime binaries
- local policy and configuration files
- local Postgres state
- receipt-signing key material
- approval verifier public-key configuration
- approval signing key material when operators issue approvals locally
- the operator controlling the machine and configuration

If the host or operator is dishonest or compromised, Aegis can emit dishonest receipts.

## What The Runtime Boundary Actually Gives You

Aegis does provide:

- a Firecracker/KVM boundary instead of direct shell execution on the host
- frozen authority at admission, bound into `authority_digest`
- explicit policy, lease, approval, and governed side-effect checks on the host
- receipts that expose what the runtime observed and enforced
- offline verification of the signed bundle

## What It Does Not Give You

Aegis does not currently provide:

- hardware attestation
- trustlessness
- proof independent of the host
- hostile-host independence
- a hosted or production-ready multi-tenant control plane
- a distributed control plane

## Signer And Verifier Assumptions

Receipt verification is meaningful only relative to a signer key you trust.

Current signer/verifier assumptions:

- receipts are signed by host-controlled key material
- runtime approval verification requires explicit verifier public-key configuration
- a receipt bundle can prove internal consistency under the bundled key, but that does not by itself prove the signer is one you intended to trust

## Lease And Approval Semantics

Lease V1 and approval tickets are different trust primitives:

- Lease V1: coarse standing authority for a covered side-effect class
- Approval ticket: exact per-attempt consent for a specific resource

Current rules:

- brokered HTTP always requires a lease
- brokered HTTP also requires approval when `require_host_consent` is enabled
- `host_repo_apply_patch` always requires both a lease and an approval ticket

## Host Patch Truth

`host_repo_apply_patch` is intentionally narrow and typed, but its lock is a local-host advisory lock.

That means:

- Aegis serializes cooperating local processes on the same host
- it does not make an arbitrary busy shared repo safe
- the truthful operating assumption is a dedicated or quiesced repo during patch application

## Operational Caveats That Matter Publicly

- Native Linux is the recommended demo host. WSL2 is useful for development, but not the cleanest validation baseline.
- Compute profiles change VM shape today; they are not yet a broader resource-envelope claim.
- Python and bash are the strongest runtime paths today. Node is supported, but less battle-tested.
- Warm pool is a latency optimization, not a second security boundary.

## What Receipt Verification Means

`aegis receipt verify --proof-dir ...` checks:

- DSSE signature validity
- artifact hash binding
- receipt schema shape
- semantic invariants for the current receipt format

It does not mean:

- the host was honest
- the host could not suppress evidence
- the execution is attested
- the execution is suitable for hostile-host or multi-tenant cloud assumptions

## Appropriate Use Today

Use Aegis when:

- one organization controls one Linux host
- you want stronger controls than direct shell or CI execution
- you need explicit post-run evidence for what the host enforced
- you can operate within the current single-host trust base

Do not treat Aegis as the right answer when:

- you need host independence
- you need attested execution
- you need a hosted multi-tenant control plane

For concrete receipt fields, use [receipt-schema.md](receipt-schema.md).
