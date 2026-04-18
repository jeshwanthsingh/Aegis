# Aegis

Aegis is a single-host Firecracker/KVM execution runtime for untrusted agent-generated code. It runs code inside a microVM, applies coarse execution policy plus optional governed-action policy, and writes host-signed DSSE receipts with proof bundles.

What it is today:

- Linux-only
- single-host
- KVM/Firecracker based
- local demo or narrow internal-pilot oriented
- host-signed receipt based, not host-attested

What it is not:

- not a Mac or Windows product
- not a hosted multi-tenant control plane
- not a production-ready enterprise deployment
- not a hardware attestation system

## Canonical happy path

This is the one setup path to lead with for a technical Linux user:

```bash
git clone https://github.com/jeshwanthsingh/Aegis.git ~/aegis
cd ~/aegis
./scripts/demo_up.sh
./scripts/demo_clean.sh
./scripts/demo_exfil_denied.sh
./scripts/demo_broker_success.sh
./scripts/demo_down.sh
```

What you need before `demo_up.sh` will work:

- Linux with `/dev/kvm` accessible to your user
- Firecracker installed, or `AEGIS_FIRECRACKER_BIN` set to the binary path
- PostgreSQL server binaries available: `initdb`, `pg_ctl`, `psql`
- Go toolchain available
- Aegis runtime assets already present:
  - `assets/vmlinux`
  - `assets/alpine-base.ext4`

`demo_up.sh` starts the local runtime on `http://127.0.0.1:8080`, initializes a local Postgres cluster under `/tmp/aegis-demo`, runs `aegis setup`, and serves the minimal demo UI on the same localhost address.

## Docs

- [Local Setup](docs/setup-local.md): the one canonical Linux/KVM setup path, prerequisites, success signals, logs, proofs, and failure modes
- [Demo Guide](docs/demo-guide.md): the three packaged demos, what each proves, what output to expect, and what receipt evidence to check
- [Trust Model](docs/trust-model.md): what the current receipts and runtime do and do not prove
- [Receipt Schema](docs/receipt-schema.md): the signed receipt contract

## Scope and trust limits

The host is in the trust base. Receipts are signed execution records produced by the host. They are useful evidence, but they are not proof against a compromised host. The current local demo path is intentionally localhost-bound and single-host.
