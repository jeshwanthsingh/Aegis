# Aegis Python SDK

Python SDK v1 for the local Aegis execution evidence runtime.

Package name:

- distribution: `aegis-sdk`
- import: `aegis`

This SDK is for the current self-hosted HTTP API exposed by `aegis serve`.

Public support posture:

- primary public path: source checkout, release assets, `aegis setup`, `aegis doctor`, `aegis serve`, then proof verification
- secondary path: this Python package talking to an already running Aegis runtime
- not-primary: package-only claims that imply the Python package also installs and boots the runtime by itself

Version coupling:

- the SDK version in this repo is `0.1.0`
- treat it as repo-coupled package metadata for this Aegis checkout, not as proof of an independently supported PyPI distribution channel

## Install

### Source checkout mode

This is the primary mode for this repo.

```bash
cd sdk/python
# Debian/Ubuntu: install python3-venv and python3-pip first if needed
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Run source-tree examples from the repo checkout:

```bash
python examples/run_code.py
```

### Installed-package mode

Secondary concern from the source checkout.

Local installed-package path from this repo:

```bash
python3 -m venv /tmp/aegis-sdk-venv
. /tmp/aegis-sdk-venv/bin/activate
pip install /path/to/Aegis/sdk/python
python - <<'PY'
from aegis import AegisClient

client = AegisClient(base_url="http://localhost:8080")
print(client.health().status)
PY
```

That path should not depend on `PYTHONPATH`, editable install, or the repo checkout being your current working directory.

It still assumes `aegis serve` is already running somewhere reachable. Installed-package mode is client consumption, not runtime installation.

Python requirement:

- Python 3.10+

## Client initialization

```python
from aegis import AegisClient

client = AegisClient(
    base_url="http://localhost:8080",
    api_key=None,
    timeout=30.0,
    cli_path=None,
)
```

Configuration precedence:

- `base_url` constructor argument
- `AEGIS_BASE_URL`
- `AEGIS_URL`
- default `http://localhost:8080`

API key precedence:

- `api_key` constructor argument
- `AEGIS_API_KEY`
- no API key configured

`GET /v1/health` is always unauthenticated. Execution endpoints require `Authorization: Bearer <token>` only when the server is started with `AEGIS_API_KEY`.

## Execute

### Inline request

```python
from aegis import AegisClient

client = AegisClient()
result = client.run(language="bash", code="echo hello from python sdk", timeout_ms=10_000)

print(result.stdout.strip())
print(result.ok, result.exit_code, result.execution_id)
```

For the canonical source-checkout onboarding path, prefer:

```bash
python examples/run_code.py
```

### Reusable request object

```python
from aegis import AegisClient, ExecutionRequest

client = AegisClient()
request = ExecutionRequest(language="bash", code="echo reusable request", timeout_ms=10_000)
result = client.run(request)
print(result.execution_id)
```

## Streaming

```python
from aegis import AegisClient, DoneEvent, ProofEvent, StdoutEvent

client = AegisClient()

for event in client.stream(language="bash", code="echo stream path"):
    if isinstance(event, StdoutEvent):
        print(event.chunk, end="")
    elif isinstance(event, ProofEvent):
        print("\nproof:", event.proof_bundle.receipt_path)
    elif isinstance(event, DoneEvent):
        print("\ndone:", event.exit_code, event.duration_ms)
```

Streaming is the advanced path. For most callers, `client.run(...)` is the simpler integration surface.

## Receipts and verification

Receipt verification uses the existing Aegis CLI verifier rather than re-implementing signing logic in Python.

Lookup order:

- `cli_path` passed to `AegisClient`
- `AEGIS_CLI_BIN`
- repo-local `.aegis/bin/aegis`
- `aegis` on `PATH`

```python
from aegis import AegisClient

client = AegisClient()
result = client.run(language="bash", code="echo verify me")

verification = result.verify_receipt()
print(verification.verified, verification.execution_id)

receipt = result.require_receipt()
print(receipt.verdict, receipt.signing_mode, receipt.key_source)
```

Direct verification is also available:

```python
verification = client.verify_receipt(proof_dir=result.proof_dir)
```

## Broker examples

Reference examples:

- `examples/broker_allowed.py`
- `examples/broker_denied.py`

These are local examples against a running orchestrator. They require the host broker credential environment to be present when `aegis serve` starts.

The stronger product proof path after first success is:

```bash
python3 ../../scripts/run_canonical_demo.py --serve
```

That is not the first-run onboarding path.

Installed-package usage is also not the first-run onboarding path. It is the package-consumption path once the runtime is already understood.

## Error model

Transport and API failures raise exceptions:

- `AegisConnectionError`
- `AegisConfigurationError`
- `AegisAuthError`
- `AegisValidationError`
- `AegisVerificationError`
- `AegisStreamError`

Runtime execution failure is distinct:

- `POST /v1/execute` may return `200 OK` for an accepted execution whose runtime outcome is unsuccessful
- those cases come back as `ExecutionResult` with `result.ok == False`

```python
result = client.run(language="bash", code="exit 2")
print(result.ok)
print(result.error)
result.raise_for_execution_error()
```

## Caveats

- this SDK targets a running local or self-hosted Aegis server
- it does not imply a hosted service, attestation, or HSM/KMS-backed signing custody
- broker examples are real, but they still depend on host-side broker credential configuration
- receipt verification depends on the Aegis CLI being available
