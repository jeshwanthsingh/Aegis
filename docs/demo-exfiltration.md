# Demo Exfiltration

This is the primary repo-native Phase 1 proof.

It uses the local HTTP API only. It does not use MCP.

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
aegis setup
aegis serve
```

Then run the Aegis-backed proof:

```bash
python3 scripts/demo_exfil_aegis.py
```

Defaults:

- receiver URL: `http://127.0.0.1:8081`
- Aegis base URL: `http://localhost:8080`

Override them with `RECEIVER_URL` and `AEGIS_BASE_URL` when needed.
