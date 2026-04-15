# Architecture

Aegis is a local execution evidence platform. The runtime is split across a host-side control plane and a Firecracker-backed guest execution plane, with proof generation and verification kept explicit.

## System view

<p align="center">
  <img src="docs/architecture-diagram.png" alt="Aegis architecture: clients enter through API/orchestrator, host-side governance evaluates policy, Firecracker guest executes code, broker mediates credential access, direct egress is denied, and proof bundles are produced on the host." width="1100" />
</p>

## Component responsibilities

### Clients

- CLI for setup, serve, health, and receipt verification
- Python SDK v1 and TypeScript SDK v1 for programmatic execution and verification
- MCP wrapper v1 for agent-tool integration, including Claude Code interoperability

### HTTP API

The API is the stable local execution surface:

- `POST /v1/execute`
- `POST /v1/execute/stream`
- `GET /v1/health`
- `GET /v1/events/{exec_id}`
- `GET /v1/stats`
- `GET /ready`
- `DELETE /v1/workspaces/{id}`

It is optionally guarded by `AEGIS_API_KEY`. Health remains unauthenticated for operator readiness checks.

### Orchestrator

The orchestrator is the host-side control loop. It:

- validates requests
- resolves the active policy and compute profile
- manages worker slots and warm-pool claims
- boots or resumes a Firecracker VM
- connects to the guest over virtio-vsock
- collects telemetry and emits proof material

### Policy and divergence engines

Policy and divergence are separate concerns:

- the point evaluator decides whether guest behavior matches the declared contract
- the divergence evaluator records and classifies runtime deviations
- enforcement outcomes are reflected in receipts and API results instead of being hidden behind generic errors

### Credential broker

The broker is host-mediated and policy-aware:

- guest code does not receive raw host secrets
- allowed and denied broker requests are both visible in proof artifacts
- upstream access happens through the broker surface, not by direct secret injection into the guest

### Firecracker microVM and guest-runner

The guest side is intentionally small:

- a Firecracker microVM provides the hardware-backed isolation boundary
- `guest-runner` receives payloads, launches the requested interpreter, streams stdout/stderr chunks, and emits runtime telemetry
- host-side policy and broker decisions remain outside the guest trust boundary

### Proof generation and verification

After execution, Aegis emits:

- a signed receipt
- a proof bundle directory
- receipt summary and public-key material needed for verification

Verification is available through:

- `aegis receipt verify`
- SDK receipt-verifier helpers
- MCP `aegis_verify`

## Trust boundaries

### Client to orchestrator

Clients trust the host runtime to enforce the declared policy and to return proof artifacts that can later be verified.

### Host to guest

The host and guest are separated by the Firecracker microVM boundary and communicate over virtio-vsock. The guest is treated as untrusted execution space.

### Broker to upstream

The broker runs on the host side and mediates credentialed requests to upstream systems. The guest can request broker actions, but it does not receive the raw credential material.

### Signer to verifier

Execution and verification are deliberately separate. Verification consumers should treat receipts as artifacts to validate, not as self-authenticating runtime claims.

## Warm pool v1

Warm pool is an optimization layer, not a separate architecture:

- preboots and pauses default-profile scratch VMs
- resumes a warm VM for one execution
- tears it down after use
- falls back to cold boot when the request is outside the current warm-path scope

Warm coverage is intentionally limited today. See [warm_pool.md](warm_pool.md).

## Design boundaries

Aegis is designed to be:

- self-hosted
- evidence-producing
- operator-usable
- developer-usable through SDKs and MCP

It is not currently designed to be:

- a hosted multi-tenant platform
- an attested trust fabric
- an HSM/KMS-backed signing system
- a general-purpose orchestration platform for every agent use case
