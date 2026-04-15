# Aegis

[![CI](https://github.com/jeshwanthsingh/Aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/jeshwanthsingh/Aegis/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](SECURITY.md)

**Aegis runs untrusted code in Firecracker microVMs, enforces policy over what that code can do, brokers credential access so secrets never enter the guest, and produces signed receipts you can verify after the run.**

```python
from aegis import AegisClient

client = AegisClient()
result = client.run(lang="python", code='print("hello")')

print(result.stdout)              # hello
print(result.receipt.verdict)     # allow / warn / deny
print(result.receipt.verify())    # True
print(result.proof_dir)           # /tmp/aegis/proofs/...
```

Run code. Get output. Get a signed receipt. Keep a proof bundle.

## What this gives you

Aegis is a self-hosted execution runtime for code you don't trust with your host. It is built for teams running AI agent workflows where isolation alone isn't enough — where you also need evidence of what happened, policy over what was allowed, and credential handling that doesn't leak secrets into the execution environment.

- **Hardware-isolated execution.** Each run happens inside a Firecracker microVM with its own kernel. Not a container. Not a namespace. A VM boundary.
- **Policy enforcement.** Cedar-based intent contracts define what code can read, write, connect to, and spawn. Violations are detected and enforced, not just logged.
- **Credential brokering.** The guest never sees raw secrets. It asks for an action over vsock, the host evaluates policy, and the guest gets the result. Validated with zero token leakage in stdout, stderr, and proof files across both allowed and denied paths.
- **Signed receipts and proof bundles.** Every execution produces an in-toto/DSSE signed receipt binding artifacts, verdicts, and enforcement actions to the execution. Receipts can be verified independently after the run.
- **Divergence detection with enforcement.** When behavior exceeds the declared contract, the runtime can warn or kill the VM. Enforced outcomes are recorded in the receipt.
- **Warm pool.** Pre-booted VMs cut dispatch latency from ~2400 ms to 15 ms on the host-side path for default-profile executions.

## Architecture

<p align="center">
  <img src="docs/architecture-diagram.png" alt="Aegis architecture: clients enter through API/orchestrator, host-side governance evaluates policy, Firecracker guest executes code, broker mediates credential access, direct egress is denied, and proof bundles are produced on the host." width="1100" />
</p>

The host side handles policy, brokerage, telemetry collection, and receipt signing. The guest side runs untrusted code inside a Firecracker microVM. Secrets stay on the host. Receipts are produced on the host after execution. Verification is separate from execution so downstream systems can validate what happened without trusting the executor.

More detail in [docs/architecture.md](docs/architecture.md).

## Quick start

Prerequisites: Linux with `/dev/kvm`, PostgreSQL running locally, `sudo` access for bootstrap.

```bash
git clone https://github.com/jeshwanthsingh/Aegis.git ~/aegis
cd ~/aegis
bash scripts/install.sh
aegis setup
aegis doctor
aegis serve
```

`scripts/install.sh` downloads Firecracker, the guest kernel, and the Alpine rootfs, builds the orchestrator, and initializes the local database. After that, `aegis setup` generates local config and signing keys, `aegis doctor` checks readiness, and `aegis serve` starts the runtime.

Then run the exfiltration demo in a second terminal:

```bash
python3 scripts/demo_receiver.py        # start a local listener
bash scripts/demo_exfil_baseline.sh      # without Aegis: data leaves
python3 scripts/demo_exfil_aegis.py      # with Aegis: blocked + receipt
```

Full stranger-first walkthrough in [docs/quickstart.md](docs/quickstart.md).

## Blocked exfiltration proof

Without Aegis, a script reads a secret and sends it to an endpoint. It works silently.

With Aegis, the same attempt is denied and the runtime produces a signed receipt:

```
EXFIL_FAILED
denial_marker=direct_egress_denied
verification=verified
```

Key receipt fields from an actual run:

```
denial_rule_id=governance.direct_egress_disabled
target=tcp://127.0.0.1:8081
verification=verified
signing_mode=dev
```

The receipt can be independently verified with `aegis receipt verify --proof-dir /path/to/proof`.

## SDKs

### Python

```bash
cd sdk/python
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
python examples/run_code.py
```

```python
from aegis import AegisClient

client = AegisClient()
result = client.run(language="bash", code="echo proof-demo")
print(result.stdout.strip())

verification = result.verify_receipt()
print(verification.verified, verification.execution_id)
```

### TypeScript

```bash
cd sdk/typescript
npm install
npx ts-node examples/run_code.ts
```

```typescript
import { AegisClient } from '@aegis/sdk'

const client = new AegisClient()
const result = await client.run({ lang: 'bash', code: 'echo proof-demo' })
console.log(result.stdout)
console.log(result.receipt.verdict)
```

Both SDKs are client packages that talk to a running Aegis runtime. They are not the runtime distribution.

## MCP server

Aegis exposes `aegis_execute` and `aegis_verify` as MCP tools over stdio. Any MCP-compatible client can discover and call them.

```bash
go build -o .aegis/bin/aegis-mcp ./cmd/aegis-mcp
AEGIS_BASE_URL=http://localhost:8080 ./.aegis/bin/aegis-mcp
```

Claude Code has been validated discovering and using both tools. Add Aegis to your MCP config and the next time your agent needs to run code, it calls `aegis_execute` and gets hardware isolation plus a verifiable receipt.

More detail in [docs/mcp_server.md](docs/mcp_server.md).

## When to use Aegis

- You run AI agent code against real systems and need evidence of what happened
- You need to prove execution behavior to a compliance team, audit, or downstream system
- You need credential access without giving the guest raw secrets
- You need policy enforcement that kills violations, not just logs them
- You want a self-hosted runtime you control, not a managed cloud sandbox

## When not to use Aegis

- You only need a casual dev sandbox
- A container or process sandbox is already sufficient for your trust model
- You need ultra-low-latency high-volume execution where the evidence overhead is too heavy
- You need host attestation, HSM/KMS signing custody, or multi-tenant trust guarantees today

## Trust model

The host is in the trust base. Receipts are signed host-side execution records. There is no host attestation today. Signing custody is local. A compromised host could produce false receipts.

What receipts prove: what the host observed and enforced during execution, cryptographically bound to the execution ID and artifacts.

What receipts do not prove: that the host itself is trustworthy, that the signing key has not been compromised, or that the observation is complete.

Full trust model in [docs/trust-model.md](docs/trust-model.md). Receipt schema in [docs/receipt-schema.md](docs/receipt-schema.md).

## Project structure

```
cmd/             CLI, MCP server, orchestrator entrypoints
internal/        host runtime: API, broker, policy, executor, pool, receipt
guest-runner/    execution runner inside the Firecracker microVM
guest-proxy/     guest-side proxy for host-mediated flows
sdk/             Python and TypeScript client SDKs
scripts/         install, bootstrap, demo, smoke, hardening
docs/            quickstart, architecture, API, MCP, trust model, receipt schema
configs/         default and validation policy files
db/              database schema and bootstrap
tests/           scenario and regression coverage
```

## Documentation

| Topic | Path |
|---|---|
| Quickstart | [docs/quickstart.md](docs/quickstart.md) |
| Exfiltration demo | [docs/demo-exfiltration.md](docs/demo-exfiltration.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| API | [docs/api.md](docs/api.md) |
| MCP server | [docs/mcp_server.md](docs/mcp_server.md) |
| Trust model | [docs/trust-model.md](docs/trust-model.md) |
| Receipt schema | [docs/receipt-schema.md](docs/receipt-schema.md) |
| Warm pool | [docs/warm_pool.md](docs/warm_pool.md) |
| Troubleshooting | [docs/troubleshooting.md](docs/troubleshooting.md) |
| Security | [SECURITY.md](SECURITY.md) |
| Python SDK | [sdk/python/README.md](sdk/python/README.md) |
| TypeScript SDK | [sdk/typescript/README.md](sdk/typescript/README.md) |

## Status

Strong enough to evaluate now. Not claiming production-hardened.

What works: Firecracker execution, Cedar policy, divergence detection with enforcement, credential broker with validated allow/deny flows, signed receipts and proof bundles, setup/serve operator workflow, Python SDK, TypeScript SDK, MCP server, warm pool for default-profile executions.

What is not built yet: host attestation, HSM/KMS signing custody, gVisor backend, full adversarial hardening suite, multi-tenant orchestration.

## Security

See [SECURITY.md](SECURITY.md) for the security model, trust boundaries, current limitations, and vulnerability reporting.

## License

[Apache-2.0](LICENSE)
