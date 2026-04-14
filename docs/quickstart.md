# Quickstart

This is the canonical first-run path for a stranger starting from a fresh source checkout.

The goal is narrow: bring up the local runtime in `~/aegis`, run the repo-native blocked-exfil demo, and verify the result.

## Host prerequisites

- Linux with `/dev/kvm`
- PostgreSQL reachable from the configured database URL
- Firecracker available on `PATH` or configured in `.aegis/config.yaml`
- `sudo` for the parts of `scripts/install.sh` that install or prepare host dependencies
- `python3` for the repo-native demo scripts
- `python3-venv` and `python3-pip` only if you later want to run SDK examples

## Clone into the canonical path

```bash
git clone https://github.com/jeshwanthsingh/Aegis.git ~/aegis
cd ~/aegis
```

## Install

```bash
bash scripts/install.sh
```

What this does in the current Phase 1 path:

- fetches or validates release assets needed for local runtime startup
- builds the canonical repo-local binaries in `~/aegis/.aegis/bin`
- links `~/.local/bin/aegis` to `~/aegis/.aegis/bin/aegis`
- rebakes `guest-runner` into the repo-local rootfs image
- initializes or reapplies the local schema at the configured Postgres URL

## Setup

```bash
aegis setup
```

This is the canonical repo-native bootstrap step. It creates or reuses `.aegis/config.yaml`, builds repo-local binaries, and prints the readiness report.

Expected Phase 1 signals:

- `Aegis CLI binary: /home/.../aegis/.aegis/bin/aegis`
- `Aegis MCP binary: /home/.../aegis/.aegis/bin/aegis-mcp`
- `` `aegis` command path: /home/.../.local/bin/aegis ``

## Doctor before serve

```bash
aegis doctor
```

Before the runtime is up, `aegis doctor` should honestly report that the runtime is unavailable. That is expected at this step.

## Serve

```bash
aegis serve
```

Leave `aegis serve` running in its own terminal.

## Doctor after serve

In another terminal:

```bash
aegis doctor
```

Expected Phase 1 outcome:

- `host_ready=PASS`
- `runtime_ready=PASS`
- `execution_path_ready=PASS`
- `receipt_path_ready=PASS`

## Run the repo-native exfil demo

Open a second terminal for the receiver:

```bash
cd ~/aegis
python3 scripts/demo_receiver.py
```

Open a third terminal for the baseline host-path exfil:

```bash
cd ~/aegis
bash scripts/demo_exfil_baseline.sh
```

Expected baseline output:

- receiver prints `RECEIVED: TOP_SECRET=demo-key-123`
- script prints `EXFIL_ATTEMPT_SENT`

Then run the Aegis-backed proof:

```bash
cd ~/aegis
python3 scripts/demo_exfil_aegis.py
```

Expected Aegis output:

- `EXFIL_FAILED`
- `verification=verified`
- `denial_marker=direct_egress_denied`
- `denial_rule_id=governance.direct_egress_disabled`

## Verify what that result means

- The baseline script proved the host can send the secret directly to the local receiver.
- The Aegis-backed script proved the same direct egress path was denied inside the Firecracker-backed runtime.
- The receipt verification output proved the host wrote a signed execution record tying that denial to the execution ID and proof bundle.

For the trust limits of that proof, read [trust-model.md](trust-model.md).

## If something is off

Use [troubleshooting.md](troubleshooting.md).

The explicit recovery path for stale repo-local state is:

```bash
cd ~/aegis
rm -rf .aegis
aegis setup
```
