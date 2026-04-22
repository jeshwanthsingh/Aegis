# Aegis

Aegis is a single-host governed execution runtime for untrusted AI-generated code. It runs code inside Firecracker/KVM microVMs, keeps current host-side side effects explicit, and emits host-signed receipts that you can verify offline.

Aegis is for platform, security, and infrastructure engineers who need something stricter than "run the agent on a shell or CI runner and keep the logs."

## What Problem It Solves

Aegis is meant to make three things true at the same time:

- untrusted agent code runs away from the host
- the current host-side side effects stay explicit and narrow
- each run ends with a signed record of what the host allowed, denied, and observed

## Architecture At A Glance

1. Admission freezes authority and computes digests before VM start.
2. Execution runs inside Firecracker/KVM under `guest-runner`.
3. The only current governed side-effect paths are brokered HTTP and typed `host_repo_apply_patch`.
4. The host enforces policy, lease, and approval checks before side effects.
5. The host writes a DSSE-signed receipt plus proof bundle.
6. `aegis receipt verify` re-checks that bundle offline.

See [Architecture](docs/architecture.md) for the full path.

## Exact Prerequisites

Current demo/setup requires all of the following on the host or in the checkout:

- Linux with accessible `/dev/kvm`
- Firecracker on `PATH` or via `AEGIS_FIRECRACKER_BIN`
- PostgreSQL server binaries: `initdb`, `pg_ctl`, `psql`
- Go
- Python 3
- `assets/vmlinux`
- `assets/alpine-base.ext4`
- repo-local `.aegis/` setup state, including config and receipt signing seed

Source of truth on the current machine:

```bash
python3 ./scripts/aegis_demo.py preflight
```

## Fastest Honest First Run

```bash
git clone https://github.com/jeshwanthsingh/Aegis.git aegis
cd aegis
python3 ./scripts/aegis_demo.py preflight
go run ./cmd/aegis-cli setup --config .aegis/config.yaml
python3 ./scripts/aegis_demo.py preflight
./scripts/demo_up.sh
python3 ./scripts/aegis_demo.py broker-http
```

That demo prints `execution_id`, `proof_dir`, and the exact `verify_command` to rerun. When finished:

```bash
./scripts/demo_down.sh
```

Use [Setup Local](docs/setup-local.md) for the full bootstrap path and failure handling. Use [Canonical Demos](docs/canonical-demos.md) for the full A-D demo set.

## Canonical Docs

- Setup / install: [docs/setup-local.md](docs/setup-local.md)
- Canonical demos: [docs/canonical-demos.md](docs/canonical-demos.md)
- Architecture: [docs/architecture.md](docs/architecture.md)
- Trust model: [docs/trust-model.md](docs/trust-model.md)
- Receipt schema: [docs/receipt-schema.md](docs/receipt-schema.md)
- Troubleshooting: [docs/troubleshooting.md](docs/troubleshooting.md)
- Security FAQ: [docs/security-faq.md](docs/security-faq.md)
- HTTP API: [docs/api.md](docs/api.md)

## What Aegis Does Not Claim

Aegis today is intentionally narrower than an attested or trustless system.

- no hardware attestation
- not trustless
- not host-independent
- not authority-complete
- not a hosted or multi-tenant control plane
- not a general shared-repo safety guarantee for `host_repo_apply_patch`

`aegis receipt verify` proves signed bundle integrity and current receipt semantics. It does not prove host honesty.

The most accurate short description today is:

> Runtime + Verify on one host you already trust.

For vulnerability reporting, use [SECURITY.md](SECURITY.md). For current trust limits and operator assumptions, use [docs/trust-model.md](docs/trust-model.md).
