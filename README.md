# Aegis

Aegis is a single-host Firecracker/KVM runtime for running untrusted agent-generated code on a Linux machine under a host-enforced execution boundary and emitting host-signed DSSE receipts.

It exists for platform and security engineers who need a real local execution boundary, a governed outbound story, and reviewable execution evidence after a run. Today it is for Linux hosts you already trust. It is not a hosted service.

## What Aegis Is Today

- Linux-only
- single-host
- Firecracker/KVM based
- no network by default, plus explicit `egress_allowlist` policy and governed brokered paths
- host-signed DSSE receipts with offline verification
- packaged local demos plus a minimal operator UI
- suitable for local validation and narrow internal pilots

## What Aegis Is Not

- not a production-ready multi-tenant platform
- not hardware attestation
- not trustless verification
- not a general agent governance cloud
- not enterprise IAM
- not Authority; that is future work, not a current product surface

## Fastest Local Path

```bash
git clone https://github.com/jeshwanthsingh/Aegis.git ~/aegis
cd ~/aegis
./scripts/demo_up.sh
./scripts/demo_clean.sh
./scripts/demo_exfil_denied.sh
./scripts/demo_down.sh
```

This path assumes Linux + KVM, Firecracker, PostgreSQL server binaries, Go, and the required runtime assets. For the exact tested baseline, asset source, and full demo sequence, use [setup-local.md](docs/setup-local.md) and [demo-guide.md](docs/demo-guide.md).

## Packaged Demos

- `./scripts/demo_clean.sh`: clean execution with a verified receipt
- `./scripts/demo_exfil_denied.sh`: direct outbound attempt denied and recorded as governed-action denial evidence
- `./scripts/demo_broker_success.sh`: brokered outbound HTTP allowed and recorded as governed-action allow evidence

## Trust Scope

Receipts are host-signed execution records. `receipt verify` proves receipt integrity, artifact binding, and semantic consistency under the receipt verification key. It does not prove hardware attestation, host honesty, or multi-tenant cloud-grade isolation. The host and operator remain in the trust base.

## Read More

- [Local Setup](docs/setup-local.md)
- [Demo Guide](docs/demo-guide.md)
- [Trust Model](docs/trust-model.md)
- [Receipt Model](docs/receipt-model.md)
- [MCP Server](docs/mcp_server.md)
