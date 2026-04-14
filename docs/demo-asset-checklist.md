# Demo Asset Checklist

This is the minimum outreach package for a self-hosted Aegis pilot conversation.

## 1. Side-by-side screenshot

One static image with two labeled panes.

- left pane: baseline host run showing `EXFIL_ATTEMPT_SENT` and receiver output `RECEIVED: TOP_SECRET=demo-key-123`
- right pane: Aegis-backed run showing `EXFIL_FAILED` and the verifier lines `verification=verified`, `denial_marker=direct_egress_denied`, `denial_rule_id=governance.direct_egress_disabled`

Requirements:

- use the repo-native demo only
- keep terminal chrome visible enough to show this is local and self-hosted
- crop tightly enough that the exact outputs are readable at slide size

## 2. Short verifier snippet

Use a 6-10 line text block taken from `aegis receipt verify --proof-dir ...`.

Required lines:

- `verification=verified`
- `execution_id=...`
- `policy_digest=...`
- `signer_key_id=...`
- `signing_mode=...`
- `trust_limitations=...`
- `denial_marker=direct_egress_denied`
- `denial_rule_id=governance.direct_egress_disabled`

Do not paste the entire summary. The point is to show the trust-critical fields, not every artifact line.

## 3. Short demo video outline

Target length: 60-90 seconds.

Sequence:

1. show the local receiver waiting
2. run the baseline script and show the secret arrive
3. show `aegis serve` already running in `~/aegis`
4. run `python3 scripts/demo_exfil_aegis.py`
5. pause on the verifier output lines
6. close with one sentence: same payload, different execution boundary, signed record afterward

## 4. Concise live-demo flow

Target length: 5-7 minutes.

Flow:

1. state the wedge: internal coding agents, not general AI governance
2. show the receiver and baseline exfil result
3. show the canonical `~/aegis` runtime path
4. run the Aegis-backed demo
5. rerun `aegis receipt verify --proof-dir ...`
6. explain what the receipt proves and what it does not prove
7. stop after the trust boundary is clear

## 5. Messaging guardrails

- say "self-hosted pilot" and "internal coding agents"
- say "signed host-side receipts" or "signed execution records"
- say "direct egress denied by default" only when showing the canonical demo or configured pilot path
- do not drift into hosted platform language, multi-tenant claims, or speculative roadmap talk
