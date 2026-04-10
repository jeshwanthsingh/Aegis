# Quickstart

This is the fastest honest path from a fresh checkout to a verified proof bundle.

## What you need

- Linux with `/dev/kvm`
- Firecracker installed or configured in `.aegis/config.yaml`
- PostgreSQL reachable from the configured database URL
- cgroups v2 enabled
- guest assets present in `assets/`
- `mkfs.ext4` available from `e2fsprogs`

WSL2 is useful for development, but native Linux is the intended local-serve target.

## 1. Install the CLI wrapper

```bash
bash scripts/install.sh
```

This gives you an `aegis` command on your path.

## 2. Bootstrap the local runtime

```bash
aegis setup
```

`aegis setup` is idempotent. It creates local config and generated binaries, prepares proof and workspace directories, and prints a readiness report with `OK`, `WARN`, and `FAIL` checks. It is the authoritative source for what is missing on your host.

## 3. Start the orchestrator

```bash
aegis serve
```

`aegis serve` prints the active config, API URL, warm-pool posture, broker-demo posture, auth posture, and receipt-signing posture before starting the HTTP server in the foreground.

Default local URL:

```text
http://localhost:8080
```

## 4. Run code and collect a proof

Python is the fastest reference path because it exercises the current public SDK cleanly without extra build steps.

```bash
cd sdk/python
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
python - <<'PY'
from aegis import AegisClient

client = AegisClient()
result = client.run(language="bash", code="echo hello from aegis")
print("stdout:", result.stdout.strip())
print("execution_id:", result.execution_id)
print("proof_dir:", result.proof_dir)
PY
```

You should see:

- guest stdout
- a stable execution ID
- a proof directory on disk

## 5. Verify the receipt

CLI path:

```bash
aegis receipt verify --proof-dir /path/to/proof-dir
```

SDK path:

```bash
python - <<'PY'
from aegis import AegisClient

client = AegisClient()
verification = client.verify_receipt(proof_dir="/path/to/proof-dir")
print("verified:", verification.verified)
print("execution_id:", verification.execution_id)
print("signing_mode:", verification.signing_mode)
PY
```

## 6. Optional: broker path

Broker flows require the orchestrator to be started from a shell where the broker credential environment is present. The broker path is policy-governed and proof-producing, but it is not auto-enabled by `aegis setup`.

Reference examples:

- `sdk/python/examples/broker_allowed.py`
- `sdk/python/examples/broker_denied.py`
- `sdk/typescript/examples/broker_allowed.ts`
- `sdk/typescript/examples/broker_denied.ts`

## Common setup failures

- `/dev/kvm` missing or not writable
  - enable KVM and add your user to the `kvm` group
- Firecracker missing
  - install Firecracker or set `runtime.firecracker_bin`
- database connection fails
  - start PostgreSQL and rerun `aegis setup`
- cgroup parent not writable
  - provide a writable delegated cgroup parent
- networking demos fail
  - ensure `ip`, `iptables`, `/dev/net/tun`, and the required privileges are available

## What this quickstart proves

- Aegis can boot a Firecracker-backed execution path
- a client can submit code through the supported public API
- a proof bundle is written locally
- the receipt can be verified after execution

## What it does not prove

- hosted multi-tenant readiness
- host attestation
- HSM/KMS-backed signing custody
- universal warm-path coverage across all request shapes
