# Aegis

Aegis is a single-host Firecracker/KVM runtime for teams that need governed execution of AI-generated code, explicit host-side side-effect controls, and host-signed receipts they can verify afterward.

It is built for platform, security, and infrastructure engineers who already trust one Linux host and want stronger execution controls than “run the agent in a shell and keep the logs.”

## Why It Exists

AI-generated code becomes operationally useful before it becomes trustworthy.

The hard part is not only isolating guest code. The harder part is making host-visible authority explicit:

- what the execution was allowed to do
- what host-side or outbound actions it requested
- what was denied
- what required explicit approval
- what the host observed and signed

Aegis is the current local answer to that problem.

## What Aegis Does Today

- runs untrusted code inside a Firecracker microVM on one Linux host
- freezes authority at admission and binds it into `authority_digest`
- evaluates policy before side effects
- issues short-lived leases for covered side-effect classes
- requires exact approval tickets for brokered HTTP under host consent and for `host_repo_apply_patch`
- supports one current host-destructive class: `host_repo_apply_patch`
- emits DSSE-signed receipts and proof bundles with offline verification

Current covered side-effect classes:

- brokered outbound HTTP
- `host_repo_apply_patch`

## Architecture At A Glance

1. Admission validates the request, freezes authority, and computes `policy_digest` and `authority_digest`.
2. If the frozen action set includes lease-covered classes, Lease V1 is issued and persisted before the VM starts.
3. A Firecracker microVM starts the guest workload under `guest-runner`.
4. Guest side effects reach the host only through the current governed paths:
   - brokered HTTP
   - typed `host_repo_apply_patch`
5. The host broker enforces:
   - canonicalization
   - policy
   - lease verification
   - approval verification when required
   - atomic lease-budget and approval consume
6. Raw runtime evidence is collected and signed into a receipt plus proof bundle.
7. `aegis receipt verify` re-checks the bundle and signed semantics offline.

Core docs:

- [Architecture](docs/architecture.md)
- [Trust Model](docs/trust-model.md)
- [Receipt Schema](docs/receipt-schema.md)

## Canonical Demo Path

The current canonical demos prove the implemented control plane, not a hypothetical future system.

Preflight first:

```bash
python3 ./scripts/aegis_demo.py preflight
```

Start the local runtime:

```bash
./scripts/demo_up.sh
```

Run the canonical suite:

```bash
python3 ./scripts/aegis_demo.py canonical-suite
```

Or run the current canonical demos individually:

- `./scripts/demo_escalation_termination.sh`
- `./scripts/demo_host_patch_denied.sh`
- `./scripts/demo_host_patch_approved.sh`
- `./scripts/demo_broker_http.sh`

Stop the runtime:

```bash
./scripts/demo_down.sh
```

See [Canonical Demos](docs/canonical-demos.md) for exact commands, expected outcomes, approval-ticket flow, and receipt verification.

## Prerequisites

Aegis is not clone-and-run yet. The current demo/runtime path requires visible local prerequisites:

- Linux
- `/dev/kvm`
- Firecracker
- PostgreSQL server binaries
- Go
- Python 3 for demo helpers
- required kernel/rootfs/assets
- repo-local `.aegis` setup state and local config

Use:

```bash
python3 ./scripts/aegis_demo.py preflight
```

to see the exact missing prerequisites on the current machine.

## What Receipts Prove

`aegis receipt verify` proves that:

- the proof bundle is complete enough to verify
- the DSSE envelope validates
- bound artifacts still hash to the signed values
- receipt semantic invariants hold for the implemented schema

It does **not** prove:

- hardware attestation
- host honesty
- trustlessness
- hostile-host independence
- multi-tenant public-cloud-grade control-plane guarantees

The host and operator remain in the trust base.

## Current Trust Limits

Important current limits:

- no attestation
- not trustless
- not a hosted multi-tenant control plane
- not a public-cloud service fabric
- host patching uses a local-host advisory lock; use a dedicated or quiesced repo, not an arbitrary busy shared repo
- approval and receipt signing are still host/operator-controlled local key material

The most accurate short description today is:

> Runtime + Verify on one host you already trust.

## Operator Commands

- `aegis demo prepare ...`
- `aegis approval issue http ...`
- `aegis approval issue host-repo-apply-patch ...`
- `aegis approval inspect ...`
- `aegis approval public-keys`
- `aegis receipt show --proof-dir ...`
- `aegis receipt verify --proof-dir ...`

## Release Readiness

For the public-push checklist and release-readiness notes, use [Release Readiness](docs/release-readiness.md).

## Further Reading

- [Setup Local](docs/setup-local.md)
- [Canonical Demos](docs/canonical-demos.md)
- [Architecture](docs/architecture.md)
- [Trust Model](docs/trust-model.md)
- [Receipt Schema](docs/receipt-schema.md)
- [Security FAQ](docs/security-faq.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Security Model](SECURITY.md)
