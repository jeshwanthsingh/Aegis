# Trust Model

Aegis today is a single-host secure execution runtime for local or internal-pilot use. It raises the bar for untrusted agent-generated code, but it is not trustless and it does not remove trust in the host.

## Product Boundary Today

- Linux only
- one host
- Firecracker/KVM runtime
- host-signed DSSE receipts
- no network by default, plus explicit `egress_allowlist` policy and governed brokered paths
- local demo and narrow internal-pilot scope

It is not:

- a production-ready multi-tenant platform
- a hosted agent governance cloud
- hardware attestation
- Authority
- a general enterprise IAM layer

## Trust Base

The trust base includes:

- the Linux host and kernel
- the Firecracker binary, kernel image, rootfs, and host-side Aegis control plane
- local policy and configuration files plus the local Postgres state
- the receipt signing seed, signer, and proof-bundle storage on the host
- the operator who controls that host and its configuration

If that host is dishonest or compromised, Aegis can produce dishonest receipts.

## What the Runtime Boundary Does

- runs untrusted code in a Firecracker microVM instead of a normal developer shell or CI runner
- keeps no-network as the default posture and uses `egress_allowlist` for the networked path: TCP 80/443 only, hard deny rules for private ranges / metadata / guest DNS, and outbound opened only for declared FQDNs or CIDRs
- records governed-action allow and deny evidence, runtime envelope data, and artifact hashes per execution
- binds that evidence into a DSSE-signed receipt and proof bundle

## What the Runtime Boundary Does Not Do

- prove the host was honest
- prove the configured policy, Firecracker binary, or VM assets were untampered
- provide hardware-rooted provenance for the host or signer
- provide cloud-grade multi-tenant isolation guarantees
- move trust out of the host or operator

## What Receipt Verification Means

`./.aegis/bin/aegis receipt verify --proof-dir <proof_dir>` checks:

- the proof bundle is complete
- bound artifacts still hash to the values named in the signed statement
- the DSSE envelope verifies
- the statement type, predicate type, and receipt semantics are valid

By default, `--proof-dir` verification uses the `receipt.pub` file inside the proof bundle. That proves the bundle is internally consistent under that public key. If a reviewer separately pins or trusts the expected signer key, the same verification also proves integrity against that trusted key.

Verification does not mean:

- hardware attestation
- trustless execution
- proof that the host could not forge, suppress, or omit evidence
- proof that the run is suitable for hostile-host or multi-tenant cloud assumptions

## What Trust Still Rests On The Host

A compromised host could:

- fabricate or suppress telemetry before signing
- sign a false receipt with the local signing key
- alter or omit proof artifacts before a reviewer fetches them
- run a different runtime or policy than the operator expected and still produce an internally consistent receipt

That is why receipts should be read as host-signed execution records, not as proof independent of the host.

## Appropriate Use Today

Aegis today is appropriate when:

- one organization controls the Linux host
- the goal is local validation or a narrow internal pilot
- reviewers want stronger execution evidence than logs alone

Aegis today is not the right fit when:

- host independence is a requirement
- hardware attestation is required
- the deployment must be multi-tenant or Internet-hosted from day one

For the concrete receipt structure and verification surface, use [receipt-model.md](receipt-model.md).
