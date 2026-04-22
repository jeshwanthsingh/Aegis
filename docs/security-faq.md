# Security FAQ

## What does Aegis try to prevent?

Aegis is trying to make untrusted AI-generated code harder to run with ambient host authority.

Today it does that by combining:

- Firecracker/KVM guest isolation
- frozen authority at admission
- host-side policy checks
- Lease V1 for covered side-effect classes
- exact approval tickets where required
- typed host-side side-effect handling
- signed receipts and offline verification

## What side effects are currently governed?

Current covered host-side side-effect classes are:

- brokered outbound HTTP
- `host_repo_apply_patch`

Unsupported host-destructive classes are denied rather than silently approximated.

## What does Aegis not prevent yet?

Aegis does **not** currently prevent:

- a dishonest or compromised host from lying
- host-side key compromise
- hardware-attestation failures, because attestation is not implemented
- arbitrary non-cooperating local processes from ignoring an advisory repo lock
- multi-tenant public-cloud threat models

## Does Aegis expose host secrets to the guest?

The current design avoids handing raw host approval or receipt signing secrets to guest code.

Important current boundaries:

- guest code requests brokered actions
- host policy/lease/approval checks stay on the host
- approval tokens can be carried through the existing broker transport, but the demo harness avoids storing them in published artifact directories
- public receipt and CLI output intentionally sanitize HTTP query strings and other secret-bearing display surfaces

## How do leases and approvals differ?

- Lease V1: coarse standing authority for a covered side-effect class
- Approval ticket: exact per-attempt approval for one specific request resource

Current rules:

- brokered HTTP always requires a lease
- brokered HTTP also requires approval when `require_host_consent` is enabled
- `host_repo_apply_patch` always requires both a lease and an approval ticket

## Is `host_repo_apply_patch` safe for any repo?

No. The truthful current statement is narrower.

The host patch path is:

- typed
- canonicalized
- policy/lease/approval mediated
- guarded by a local-host advisory lock

That lock is real and useful, but it is still advisory. The current operating assumption is a dedicated or quiesced repo during patch application.

## What does `receipt verify` prove?

It proves that a verifier checked:

- the DSSE envelope
- artifact hashes
- schema shape
- current semantic invariants

It does **not** prove:

- host honesty
- attestation
- trustlessness
- proof independent of the host

## Why is there a verifier if the host is still in the trust base?

Because “host-signed and re-checkable” is still materially better than “trust the logs.”

The verifier catches:

- broken or tampered bundles
- signature mismatches
- schema violations
- contradictory approval / lease / escalation states

It does not remove the host from the trust base.

## How should operators think about secret handling?

Current practical guidance:

- keep signing seeds and verifier public-key config out of git
- use explicit approval verifier public-key config for runtime enforcement
- do not assume demo artifacts are the right place to store reusable secrets
- treat approval tickets as scoped runtime authorization material, not as a general secret transport

For the full trust assumptions, use [trust-model.md](trust-model.md).
For the signed receipt fields, use [receipt-schema.md](receipt-schema.md).
