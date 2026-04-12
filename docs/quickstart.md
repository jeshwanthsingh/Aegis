# Quickstart

This is the canonical source-checkout onboarding path.

For a source checkout, follow this exact sequence:

1. host prerequisites
2. `aegis setup`
3. `aegis doctor`
4. `aegis serve`
5. one SDK example
6. `aegis receipt verify`

## 0. Host prerequisites

- Linux with `/dev/kvm`
- Firecracker installed or configured in `.aegis/config.yaml`
- PostgreSQL reachable from the configured database URL
- cgroups v2 enabled
- guest assets present in `assets/`
- `mkfs.ext4` available from `e2fsprogs`
- Python 3.10+ with `venv` and `pip` support for the canonical source-tree SDK example

WSL2 is useful for development, but native Linux is the intended local-serve target.

Optional automation:

```bash
bash scripts/install.sh
```

That script is convenience automation for a source checkout. It is not the primary truth surface. The primary truth surfaces are `aegis setup` and `aegis doctor`.

## 1. Bootstrap from the source checkout

```bash
aegis setup
```

`aegis setup` is idempotent. It creates repo-local config and generated binaries, prepares proof and workspace directories, and prints the authoritative readiness report for what is present or missing on this host.

## 2. Verify readiness before serving

```bash
aegis doctor
```

`aegis doctor` is the readiness gate for the supported local-serve path. It checks host/runtime access, reaches the API when available, runs a self-test execution, and verifies the emitted receipt.

Before `aegis serve` is running, the runtime checks will tell you the server is not reachable yet. That is the handoff to the next step, not a cue to guess.

## 3. Start the runtime

```bash
aegis serve
```

`aegis serve` prints the active config, API URL, warm-pool posture, broker-demo posture, auth posture, and receipt-signing posture before starting the HTTP server in the foreground.

Default local URL:

```text
http://localhost:8080
```

After `aegis serve` is up, rerun:

```bash
aegis doctor
```

That is the first fully green readiness check before you move on to SDK examples.

## 4. Run one source-tree SDK example

Python is the canonical first example for a source checkout.

Source-tree Python mode:

```bash
cd sdk/python
# Debian/Ubuntu: install python3-venv and python3-pip first if needed
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
python examples/run_code.py
```

That example prints:

- guest stdout
- execution status
- execution ID
- proof directory

## 5. Verify the emitted proof

Use the `proof_dir` printed by the example:

```bash
aegis receipt verify --proof-dir /path/to/proof-dir
```

That is the end of the primary onboarding path.

## Source checkout vs installed package usage

Source checkout Python usage:

- create the venv inside `sdk/python`
- `pip install -e .`
- run examples from `sdk/python/examples/...`

Installed-package Python usage:

- separate concern
- once the package is built/published for your environment, import `aegis` in your own project
- not the primary path for a fresh repo checkout

Source checkout TypeScript usage:

```bash
cd sdk/typescript
npm install
npm run build
node dist/examples/run_code.js
```

That path assumes Node.js and npm are already installed on the host.

Installed-package TypeScript usage:

- separate concern
- once the package is built/published for your environment, consume `@aegis/sdk` in your own project
- not the primary path for a fresh repo checkout

## Stronger second-step proof

After the first successful source-checkout run, use the stronger proof harness:

```bash
python3 scripts/run_canonical_demo.py --serve
```

That is the product proof path. It is not the first-run onboarding path.

## Optional broker path

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
