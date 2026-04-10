# Security Model

Aegis is designed to run untrusted code in hardware-isolated sandboxes and produce verifiable evidence about what happened. This document describes the security model that exists today, the threats Aegis is meant to handle, and the boundaries it does not claim to solve.

## What Aegis isolates

### Firecracker microVM boundary

Each execution runs inside a Firecracker microVM with a separate guest kernel. The guest is treated as untrusted.

### Host-mediated control plane

The host orchestrator is responsible for:

- request validation
- policy enforcement
- divergence handling
- receipt and proof generation
- credential brokerage

The guest does not become the source of truth for those decisions.

### Broker boundary

Brokered upstream access stays on the host side:

- guest code can request broker actions
- the broker decides whether the request is allowed
- upstream credentials remain host-side
- allowed and denied broker outcomes are reflected in proof artifacts

### Proof and verification boundary

Receipts and proof bundles are emitted after execution telemetry is collected. Verification is a separate step performed by the CLI, SDKs, or MCP wrapper rather than being implicitly trusted because the runtime produced the artifact.

## Threat model

Aegis is designed to handle:

- untrusted guest code
- compromised or misbehaving agent logic
- code that attempts undeclared file, process, or network behavior
- policy deviations that should be visible as divergence or denial, not hidden in generic failures
- credential use that must be brokered without raw secret disclosure to the guest
- post-execution verification requirements where logs alone are not enough

## What Aegis does not protect against

Aegis does **not** currently claim to protect against:

- host compromise
- a malicious or compromised operator
- host attestation failures, because host attestation is not implemented
- HSM/KMS custody failures, because receipt signing is not currently HSM/KMS-backed
- a fully hostile multi-tenant cloud threat model
- every form of side channel or microarchitectural leakage

If your trust model requires attested hosts, externally rooted key custody, or hardened multi-tenant cloud isolation, Aegis is not the full answer today.

## Trust boundaries

### Client, SDK, or MCP client to orchestrator

Clients trust the host runtime to execute the declared job and to return proof material that can later be verified.

### Host to guest

The guest is isolated by the Firecracker microVM boundary and reached over virtio-vsock. The host remains the policy and secret enforcement layer.

### Broker to upstream

The broker is a host-side mediator between guest intent and upstream credential use. The guest does not receive the upstream secret material directly.

### Signer to verifier

Verification consumers should treat receipts as signed artifacts to validate, not as assertions that are automatically trustworthy because they came from the runtime.

## Current trust posture

Aegis is currently positioned as a **local/self-hosted execution evidence runtime**.

Important current realities:

- it is oriented toward self-hosted operators, not a hosted trust service
- receipts can run in a more permissive local/dev posture or a stricter configured posture
- strict mode still depends on local host custody of signing material, not on HSM/KMS-backed custody
- host attestation is not present
- broker credentials are currently supplied by the host/operator environment and mediated by the broker
- warm pool is an optimization, not a distinct security boundary
- multi-tenant isolation beyond the current self-hosted model is out of scope today

## Credential broker posture

The broker path is one of Aegis's core trust features.

Current guarantees:

- allowed and denied broker paths exist and are exercised
- raw broker credentials are not exposed directly to guest code
- broker decisions are represented in proof artifacts

Current limits:

- this is still a host-operated credential model
- it is not a hosted secret-custody service
- upstream trust still depends on the host operator and host environment

## Adversarial hardening status

Aegis has already gone through adversarial hardening work, including reproduced trust bugs that were fixed in the runtime and proof-verification path.

That should increase confidence, but it should not be read as a claim that:

- the system has formal verification
- every attack class is closed
- the runtime is enterprise-attested

## “Launch-quality with caveats” in operator terms

Today that phrase means:

- the runtime, broker path, proof path, SDKs, and MCP surface are coherent enough for serious evaluation
- the project is explicit about current limits rather than smoothing them over
- some important trust upgrades are still intentionally out of scope, especially attestation, HSM/KMS custody, and broader multi-tenant posture

It does **not** mean:

- enterprise trust custody is solved
- hosted-service hardening is complete
- the operator can ignore host security

## Vulnerability reporting

If you believe you have found a security issue in Aegis:

- do not open a public issue with exploit details first
- report it privately to the maintainers through the repository contact path or GitHub security reporting flow if available
- include affected component, reproduction steps, impact, and whether proof artifacts or broker behavior are involved

If no private reporting path is configured in the repository hosting surface, open a minimal issue requesting a secure contact channel and avoid publishing weaponized details until maintainers respond.

## Security boundaries for evaluators

Use Aegis when you need:

- isolated untrusted execution
- policy-visible runtime behavior
- brokered upstream access without raw guest secret exposure
- proof artifacts that can be verified after execution

Do not treat Aegis as equivalent to:

- host attestation
- HSM-backed trust custody
- a hosted multi-tenant execution fabric
- a full secrets platform
