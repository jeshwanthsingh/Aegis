# Aegis

[![Tier 1 CI](https://github.com/jeshwanthsingh/Aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/jeshwanthsingh/Aegis/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](SECURITY.md)

**Aegis runs untrusted code in Firecracker microVMs, brokers dangerous actions through explicit policy, and gives you receipts you can verify after execution.**

Aegis is for code you should not trust with your host: agent-generated tools, brokered upstream access, and execution flows where logs are not enough.

## Start Here

- [Quickstart](docs/quickstart.md): first source-checkout path for a new operator
- [Architecture](docs/architecture.md): runtime components, control flow, and trust boundaries
- [API](docs/api.md) / [OpenAPI](docs/openapi.json): HTTP surface and schema
- [MCP Server](docs/mcp_server.md): MCP tools and client wiring
- [Canonical Demo](docs/canonical-demo.md): product demo after the runtime is already healthy
- [Security](SECURITY.md): security model, limitations, and reporting guidance

## Prerequisites

- Linux with `/dev/kvm`
- PostgreSQL running and reachable
- valid database credentials
- `python3-venv` and `python3-pip` for Python SDK examples
- `sudo` access for parts of install/bootstrap

## Run This First

```bash
git clone https://github.com/jeshwanthsingh/Aegis.git
cd Aegis
bash scripts/install.sh
aegis setup
aegis doctor
aegis serve
```

For most first-time source-checkout users, `scripts/install.sh` is effectively required. It fetches runtime assets, prepares the guest image, builds the orchestrator binary, and gets the local database/bootstrap path into a usable state before `aegis setup`, `aegis doctor`, and `aegis serve`.

The canonical demo is a second step after the runtime is healthy, not the first command for a stranger evaluating the repo.

### First-run Notes

- PostgreSQL defaults assume a standard local setup such as `postgres://postgres:postgres@localhost/aegis?sslmode=disable`.
- If your local PostgreSQL credentials differ, set `AEGIS_DB_URL` or `DB_URL` explicitly before running setup.
- A custom repo-local `.aegis/config.yaml` can cause confusing failures. If setup behaves strangely, remove `.aegis/` and rerun `aegis setup`.
- The repo-local MCP binary may need a manual build: `go build -o .aegis/bin/aegis-mcp ./cmd/aegis-mcp`.

## Why It Exists

Running untrusted code is not just a sandboxing problem. You need a real isolation boundary, explicit policy over what the code can do, and proof of what the runtime allowed, denied, and observed. Aegis exists for that shape of problem.

## What This Is

- a self-hosted execution evidence runtime
- Firecracker-backed isolation for untrusted code
- policy-governed external action instead of raw guest freedom
- proof bundles and receipts that can be verified after execution
- a local operator flow exposed through CLI, HTTP API, SDKs, and MCP

## What This Is Not

- not a package-only install story
- not a hosted multi-tenant platform
- not host attestation
- not HSM/KMS-backed signing custody
- not a generic dev sandbox with nicer branding

## Real proof: blocked exfiltration

Without Aegis, a simple script can read data and attempt an outbound request.

With Aegis, the direct egress path is denied and the runtime emits a signed receipt that can be verified independently after the run.

Key fields from an actual MCP-driven proof:

- `denial_marker=direct_egress_denied`
- `denial_rule_id=governance.direct_egress_disabled`
- `target=tcp://127.0.0.1:8081`
- `verification=verified`

## Source Checkout Quickstart

For a first-time source checkout, use the `Run This First` block above.

After the runtime is up, the minimal operator loop is:

```bash
aegis doctor
aegis serve
```

Then run one SDK example and verify the emitted proof:

```bash
cd sdk/python
# Ubuntu: install python3-venv and python3-pip first if needed
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
python examples/run_code.py
aegis receipt verify --proof-dir /path/to/proof-dir
```

For host prerequisites, asset expectations, caveats, and TypeScript source-tree mode, use [docs/quickstart.md](docs/quickstart.md).

## Distribution Posture

Primary path today: source checkout on Linux/KVM with release assets.

Secondary path: Python or TypeScript SDK usage against an already running Aegis runtime.

Not-primary: package-only claims that imply `pip install` or `npm install` also bootstraps the runtime. The SDKs are client packages for a running Aegis runtime, not the runtime distribution story by themselves.

## Release Assets And Checksums

The source-checkout runtime path expects these release artifacts:

- `firecracker`
- `vmlinux`
- `alpine-base.ext4`

Checksum contract:

- `scripts/release-checksums.txt`

For most first-time source-checkout users, `scripts/install.sh` is the practical bootstrap path. It is the step that downloads release assets, prepares the guest image, and initializes the database before `aegis setup`, `aegis doctor`, and `aegis serve`.

## What Aegis gives you

- **Hardware-isolated execution** with Firecracker microVMs and a separate guest kernel
- **Policy-governed runtime behavior** across file access, network, process scope, and time/resource budgets
- **Divergence handling** with explicit receipts for allow, warn, deny, and enforcement outcomes
- **Brokered secret-safe delegation** over vsock, including allowed and denied credential paths without raw secret exposure to guest code
- **Cryptographic receipts and proof bundles** that can be verified after execution
- **Operator-usable local runtime** with `aegis setup`, `aegis serve`, readiness reporting, and honest posture output
- **Developer-facing integrations** through Python SDK v1, TypeScript SDK v1, and MCP wrapper v1
- **Warm pool v1** for lower startup latency on the supported warm-path request shapes

## Architecture

Aegis keeps policy, brokerage, and proof generation on the host side while untrusted code runs inside a Firecracker guest. The result is a runtime where the execution boundary and the evidence path stay explicit.

```mermaid
flowchart LR
    subgraph Clients
        PY[Python SDK]
        TS[TypeScript SDK]
        MCP[MCP client / Claude Code]
        CLI[Aegis CLI]
    end

    PY --> API
    TS --> API
    CLI --> API
    MCP --> MCPSRV
    MCPSRV --> API

    subgraph Host["Aegis host runtime"]
        API[Aegis HTTP API]
        ORCH[Orchestrator]
        POL[Policy + divergence engines]
        BROKER[Credential broker]
        PROOF[Proof bundle writer]
        VERIFY[Receipt verifier]
    end

    API --> ORCH
    ORCH --> POL
    ORCH --> BROKER
    ORCH --> PROOF
    PROOF --> VERIFY

    subgraph VM["Firecracker microVM"]
        GUEST[guest-runner]
        CODE[Untrusted code]
    end

    ORCH -->|virtio-vsock| GUEST
    GUEST --> CODE
    BROKER -->|host-mediated delegation| GUEST
```

### Trust boundaries

- host and guest are separated by a Firecracker microVM boundary
- secrets stay on the host side and are exposed only through the broker policy surface
- receipts and proof bundles are produced on the host after execution telemetry is collected
- verification is separate from execution so downstream systems can validate what happened

More detail: [docs/architecture.md](docs/architecture.md)

## Project Structure

```text
.
├── cmd/            CLI, MCP server, and orchestrator entrypoints
├── internal/       host runtime packages: API, broker, policy, executor, pool, receipt
├── guest-runner/   guest-side execution runner used inside the microVM
├── guest-proxy/    guest-side proxy path for host-mediated flows
├── sdk/            Python and TypeScript client SDKs
├── scripts/        install, bootstrap, demo, smoke, and hardening scripts
├── docs/           quickstart, architecture, API, MCP, demo, and warm-pool docs
├── assets/         kernel and rootfs assets used by local runtime flows
├── configs/        default and validation policy files
├── db/             database schema and bootstrap assets
├── ui/             local proving-ground UI assets
├── tests/          repo-level scenario and regression coverage
└── .aegis/         repo-local binaries and config created during setup
```

## When to use Aegis

- you need an auditable path for untrusted agent or tool execution
- you need evidence or provenance for what code did at runtime
- you need to constrain file, process, network, and delegation behavior with explicit policy
- you need upstream access through a broker without giving the guest raw credentials
- you need a self-hosted local runtime that can also be reached through SDKs or MCP

## When not to use Aegis

- you only need a casual local dev sandbox
- a plain container, devcontainer, or process sandbox is already sufficient
- you are optimizing for ultra-low-latency, very high-volume execution where the current evidence-producing model is too heavy
- you require host attestation, HSM/KMS-backed signing custody, or enterprise multi-tenant trust guarantees today

## Status and maturity

**Launch-quality with caveats.**

Strong enough to evaluate now:

- Firecracker runtime with policy enforcement, telemetry, divergence handling, and proof generation
- brokered credential delegation with validated allowed and denied paths
- operator flow through `aegis setup` and `aegis serve`
- Python SDK v1, TypeScript SDK v1, and MCP wrapper v1
- verified receipt and proof-bundle workflow
- warm pool v1 for default-profile scratch executions

Still intentionally scoped:

- warm coverage is not universal across all profile and workspace shapes
- signing is local/self-hosted, not HSM/KMS-backed
- no host attestation
- not positioned as a hardened hosted multi-tenant control plane

Not built yet:

- host attestation
- HSM/KMS-backed receipt-signing custody
- broader multi-tenant orchestration
- alternate runtime backends such as gVisor

## Documentation

| Topic | Path |
| --- | --- |
| Quickstart | [docs/quickstart.md](docs/quickstart.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| API | [docs/api.md](docs/api.md) |
| OpenAPI | [docs/openapi.json](docs/openapi.json) |
| MCP server | [docs/mcp_server.md](docs/mcp_server.md) |
| Canonical demo | [docs/canonical-demo.md](docs/canonical-demo.md) |
| Warm pool | [docs/warm_pool.md](docs/warm_pool.md) |
| Security | [SECURITY.md](SECURITY.md) |
| Python SDK | [sdk/python/README.md](sdk/python/README.md) |
| TypeScript SDK | [sdk/typescript/README.md](sdk/typescript/README.md) |

## Example usage

### Python SDK: execute and verify

Ubuntu prerequisite:

- install `python3-venv` and `python3-pip`

```python
from aegis import AegisClient

client = AegisClient()
result = client.run(language="bash", code="echo proof-demo")
print(result.stdout.strip())

verification = result.verify_receipt()
print(verification.verified, verification.execution_id)
```

### Canonical Demo (secondary)

```bash
python3 scripts/run_canonical_demo.py
```

This shows:

- governed allow
- denied direct egress
- receipt verification

Note: broker-related steps require additional configuration. See [docs/canonical-demo.md](docs/canonical-demo.md).

### TypeScript SDK

Host prerequisites:

- Node.js 20+ recommended
- Node 18 may still work, but can emit engine warnings

### MCP: isolated execution tool

Once the MCP server is registered, clients call:

- `aegis_execute` to run code through the existing Aegis runtime
- `aegis_verify` to validate a prior proof bundle

Build the MCP binary explicitly:

```bash
go build -o .aegis/bin/aegis-mcp ./cmd/aegis-mcp
```

Then run it against a live local runtime:

```bash
AEGIS_BASE_URL=http://localhost:8080 ./.aegis/bin/aegis-mcp
```

`aegis setup` and `scripts/install.sh` do not currently build `.aegis/bin/aegis-mcp` by default. After source changes, rebuild it or the MCP binary can become stale relative to current receipt formats and verifier behavior.

The MCP wrapper stays intentionally thin. It does not bypass the HTTP API or the receipt-verification path. See [docs/mcp_server.md](docs/mcp_server.md).

## Known Local Limitations

- the guest image may not include tools like `curl`
- some commands can fail due to process policy or child-process denial
- broker flows require explicit credential configuration

## Positioning

- Aegis is centered on self-hosted governed execution with verifiable proof artifacts.
- Some alternatives are managed sandbox products first.
- Some alternatives are local dev sandboxes first.
- Some alternatives are agent platforms first.
- Aegis is for the slice of the problem where isolation, policy, and post-run verification all matter at once.

## Contributing

There is no standalone `CONTRIBUTING.md` in this repo yet. Until there is one, follow [AGENTS.md](AGENTS.md), keep changes narrow, and include the smallest verification that proves the behavior you changed.

## Security

See [SECURITY.md](SECURITY.md) for the current security model, trust boundaries, limitations, and vulnerability-reporting guidance.

## License

Aegis is licensed under [Apache-2.0](LICENSE).
