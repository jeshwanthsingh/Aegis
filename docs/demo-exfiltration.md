# Demo Exfiltration

This is the primary repo-native Phase 1 proof.

It uses the local HTTP API only. It does not use MCP.

Run it from the canonical repo path:

```bash
cd ~/aegis
```

## Expected outputs

Without Aegis:

- receiver prints `RECEIVED: TOP_SECRET=demo-key-123`
- baseline script prints `EXFIL_ATTEMPT_SENT`

With Aegis:

- demo script prints `EXFIL_FAILED`
- verifier prints `verification=verified`
- verifier prints `denial_marker=direct_egress_denied`
- verifier prints `denial_rule_id=governance.direct_egress_disabled`

## Run it

From `~/aegis`:

```bash
python3 scripts/demo_receiver.py
```

In a second shell:

```bash
bash scripts/demo_exfil_baseline.sh
```

In a third shell, bring up the repo-native runtime:

```bash
cd ~/aegis
aegis setup
aegis doctor
aegis serve
```

Then run the Aegis-backed proof:

```bash
cd ~/aegis
python3 scripts/demo_exfil_aegis.py
```

The demo script runs receipt verification itself and prints the canonical verification lines.

If you want to inspect the full trust-critical verifier output yourself, rerun:

```bash
cd ~/aegis
aegis receipt verify --proof-dir /tmp/aegis/proofs/<execution-id>
```

Default verifier output now includes fields such as:

- `policy_digest=...`
- `signer_key_id=...`
- `signing_mode=...`
- `intent_digest=...`
- `trust_limitations=...`

Defaults:

- receiver URL: `http://127.0.0.1:8081`
- Aegis base URL: `http://localhost:8080`

Override them with `RECEIVER_URL` and `AEGIS_BASE_URL` when needed.

If setup or runtime steps fail, use [troubleshooting.md](troubleshooting.md).

For what the receipt does and does not prove, use [trust-model.md](trust-model.md).
