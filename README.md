# Aegis

Aegis lets internal coding agents run code without giving them your machine, and produces signed host-side receipts showing what they tried to do.

## Who it is for

Aegis is for teams that want internal agents to execute code, touch files, and attempt external actions without handing those agents direct host access.

## First run

Canonical repo path:

```bash
git clone https://github.com/jeshwanthsingh/Aegis.git ~/aegis
cd ~/aegis
bash scripts/install.sh
aegis setup
aegis doctor
aegis serve
```

Then run the repo-native blocked-exfil proof in a second terminal flow:

```bash
python3 scripts/demo_receiver.py
bash scripts/demo_exfil_baseline.sh
python3 scripts/demo_exfil_aegis.py
```

Use [docs/quickstart.md](docs/quickstart.md) for the full stranger-first path from clone to verified demo output.

## Docs

- [Quickstart](docs/quickstart.md): clone, install, setup, doctor, serve, run the repo-native exfil demo, verify the result
- [Demo Exfiltration](docs/demo-exfiltration.md): the primary repo-native Phase 1 proof
- [Trust Model](docs/trust-model.md): what Aegis does and does not prove today
- [Receipt Schema](docs/receipt-schema.md): the canonical receipt and proof fields
- [Troubleshooting](docs/troubleshooting.md): common failures and exact recovery commands
- [MCP Server](docs/mcp_server.md): how the repo-local MCP wrapper is built and run

## Trust and limitations

The host is in the trust base. There is no host attestation today. Receipt signing custody is local today. Receipts are signed host-side execution records, not a proof that a compromised host could not lie.

Use [docs/trust-model.md](docs/trust-model.md) for the exact trust assumptions and [docs/receipt-schema.md](docs/receipt-schema.md) for what the receipt fields contribute to trust.
