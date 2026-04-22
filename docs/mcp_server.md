# MCP Server

Aegis ships an MCP stdio server so agent clients can call a local Aegis runtime without having to construct HTTP requests or parse receipt verification output themselves.

The MCP path is secondary. The canonical first-run path is [setup-local.md](setup-local.md) and [canonical-demos.md](canonical-demos.md). Aegis today is not a broad MCP platform. The server is a thin local wrapper over the same runtime and verification path.

The MCP layer is intentionally thin:

- it does not embed the orchestrator
- it does not bypass the HTTP API
- it does not replace proof verification with an MCP-only trust model

## Exposed tools

### `aegis_execute`

Runs code through the existing `POST /v1/execute` API and returns structured execution data plus proof-verification information when available.

Input schema:

```json
{
  "type": "object",
  "required": ["code", "language"],
  "properties": {
    "code": { "type": "string" },
    "language": { "type": "string", "enum": ["python", "bash", "node"] },
    "timeout_sec": { "type": "number", "default": 10 },
    "allow_network_domains": { "type": "array", "items": { "type": "string" } },
    "allow_write_paths": { "type": "array", "items": { "type": "string" } },
    "broker_delegations": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name"],
        "properties": {
          "name": { "type": "string" },
          "resource": { "type": "string" },
          "method": { "type": "string" }
        }
      }
    }
  }
}
```

Behavior:

- compiles a v1 intent contract before calling the runtime
- network is disabled unless `allow_network_domains` is supplied
- broker access is denied unless `broker_delegations` is supplied
- `allow_write_paths` must use absolute guest paths
- adds only the minimal runtime allowances needed for the selected language surface

Representative result fields:

- `execution_id`
- `ok`
- `stdout`
- `stderr`
- `exit_code`
- `exit_reason`
- `proof_dir`
- `receipt_path`
- `receipt.verified`
- `receipt.result_class`
- `receipt.divergence_verdict`
- `receipt.outcome_reason`
- `receipt.signing_mode`
- `receipt.key_source`
- `receipt.summary`
- `divergence`
- `broker`
- `verification_error`

### `aegis_verify`

Verifies an existing proof bundle through the same receipt-verification logic used by the CLI.

Input schema:

```json
{
  "type": "object",
  "properties": {
    "execution_id": { "type": "string" },
    "proof_dir": { "type": "string" }
  }
}
```

Behavior:

- requires at least one of `execution_id` or `proof_dir`
- resolves proof material locally
- returns structured verification diagnostics instead of only a string summary

Representative result fields:

- `ok`
- `execution_id`
- `proof_dir`
- `verified`
- `result_class`
- `divergence_verdict`
- `outcome_reason`
- `signing_mode`
- `key_source`
- `summary`
- `diagnostics`
- `verification_error`

## Build

If `./scripts/demo_up.sh` completed successfully, the repo-local MCP binary should already exist at `./.aegis/bin/aegis-mcp`.

If you need to rebuild it immediately after MCP source changes:

```bash
cd ~/aegis
go build -buildvcs=false -o ./.aegis/bin/aegis-mcp ./cmd/aegis-mcp
```

## Run

Bring up the local runtime first:

```bash
cd ~/aegis
./scripts/demo_up.sh
```

Then start the MCP server:

```bash
cd ~/aegis
AEGIS_BASE_URL=http://127.0.0.1:8080 ./.aegis/bin/aegis-mcp
```

Supported environment variables:

- `AEGIS_BASE_URL`
- `AEGIS_URL`
- `AEGIS_API_KEY`

## Claude Code setup

Example registration from Windows against a WSL-backed repo:

```powershell
@'
@echo off
wsl.exe bash -lc "cd ~/aegis && AEGIS_BASE_URL=http://127.0.0.1:8080 ./.aegis/bin/aegis-mcp"
'@ | Set-Content -Encoding ASCII $HOME\aegis-mcp-launch.cmd

claude mcp add -s user aegis $HOME\aegis-mcp-launch.cmd
claude mcp get aegis
```

This path was validated with Claude Code interoperability in the current repo state.

## Trust and caveats

- the MCP server is a convenience distribution surface, not a separate trust boundary
- execution still happens through the same Firecracker-backed Aegis runtime
- verification still depends on the same host-signed proof bundle and receipt-verifier path
- if the local host is compromised, MCP results and receipts can be dishonest for the same reason the base runtime can be dishonest
- safe defaults are intentional: no network and no broker delegation unless requested
- broker-backed flows still require the orchestrator to be started with the appropriate broker credential environment

If `aegis_execute` fails because the runtime is down, start `./scripts/demo_up.sh` first or use an equivalent operator-managed runtime, then use [troubleshooting.md](troubleshooting.md).
