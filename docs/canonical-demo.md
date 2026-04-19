# Canonical Demo (Deprecated)

Deprecated. Do not use this as the Aegis demo walkthrough.

The older harness-based walkthrough is not the packaged demo path the repo now leads with. The current canonical demo flow is the three script-based demos documented in [demo-guide.md](demo-guide.md).

Use these commands instead:

```bash
./scripts/demo_up.sh
./scripts/demo_clean.sh
./scripts/demo_exfil_denied.sh
./scripts/demo_broker_success.sh
./scripts/demo_down.sh
```

What those three demos prove today:

- clean execution completes and produces a signed receipt
- direct outbound exfil is denied and that denial is recorded in the receipt
- brokered outbound succeeds and is recorded as a governed allow path

For the current walkthrough, expected output, and receipt evidence, use [demo-guide.md](demo-guide.md).
