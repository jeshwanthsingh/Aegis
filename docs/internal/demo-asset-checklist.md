# Demo Asset Checklist

This is the minimum outreach package for a self-hosted Aegis pilot conversation.

## 1. Side-by-side screenshot

One static image with two labeled panes.

- left pane: packaged clean run showing `DEMO_CLEAN_OK` and `verification=verified`
- right pane: packaged denied run showing `DEMO_EXFIL_ATTEMPTED`, `verification=verified`, `denial_marker=direct_egress_denied`, and `denial_rule_id=governance.direct_egress_disabled`

Requirements:

- use the packaged demo scripts only
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

1. show `./scripts/demo_up.sh` succeeding
2. run `./scripts/demo_escalation_termination.sh`
3. run `./scripts/demo_host_patch_denied.sh`
4. pause on the verifier output lines
5. close with one sentence: same runtime, escalation is denied, host patch without approval is denied, signed record afterward

## 4. Concise live-demo flow

Target length: 5-7 minutes.

Flow:

1. state the wedge: internal coding agents, not general AI governance
2. run `./scripts/demo_up.sh`
3. run `./scripts/demo_escalation_termination.sh`
4. run `./scripts/demo_host_patch_denied.sh`
5. run `./scripts/demo_broker_http.sh`
6. rerun `./.aegis/bin/aegis receipt verify --proof-dir ...`
7. explain what the receipt proves and what it does not prove, then stop

## 5. Messaging guardrails

- say "self-hosted pilot" and "internal coding agents"
- say "signed host-side receipts" or "signed execution records"
- say "direct egress denied by default" only when showing the canonical demo or configured pilot path
- do not drift into hosted platform language, multi-tenant claims, or speculative roadmap talk
