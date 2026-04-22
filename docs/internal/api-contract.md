# Aegis SDK v1 HTTP API Contract

This document freezes the Go HTTP seam that the Python SDK v1 should target.

## Frozen SDK-facing endpoints

- `GET /v1/health`
  - Unauthenticated health check.
  - Returns worker slot availability and overall API status.
- `POST /v1/execute`
  - Primary SDK execution path.
  - Synchronous request/response.
  - Returns execution output plus proof/receipt bundle metadata when the run completes.
- `POST /v1/execute/stream`
  - Optional advanced SDK path.
  - Streams `stdout`, `stderr`, proof metadata, and final status as Server-Sent Events.

## Explicitly not frozen for SDK v1

These routes exist, but the Python SDK v1 should not depend on them yet:

- `GET /health` (legacy alias for local operator use)
- `GET /ready`
- `GET /v1/stats`
- `GET /v1/events/{exec_id}`
- `DELETE /v1/workspaces/{id}`

No `GET /v1/executions/{id}` endpoint is required for SDK v1 because the primary execute path is synchronous.
No `GET /v1/receipts/{id}` endpoint is required for SDK v1 because `POST /v1/execute` already returns host-local proof and receipt paths.

## Execution model decision

SDK v1 should use **synchronous** `POST /v1/execute` as the primary path.

Why:

- the server already blocks until the execution completes and returns the full result
- this avoids introducing polling or async state machinery that the SDK does not need yet
- proof bundle metadata is already surfaced directly on the synchronous response

`POST /v1/execute/stream` is supported as an **optional advanced** path for interactive callers that want incremental output.

## Authentication

Canonical authenticated header:

```http
Authorization: Bearer <token>
```

Rules:

- If `AEGIS_API_KEY` is **unset** on the Go orchestrator, execute endpoints run in unauthenticated local-dev mode.
- If `AEGIS_API_KEY` is **set**, `POST /v1/execute` and `POST /v1/execute/stream` require `Authorization: Bearer <token>` with an exact token match.
- `GET /v1/health` is always unauthenticated.

Missing or invalid auth returns `401` with the standard error envelope.

Example:

```json
{
  "error": {
    "code": "auth_required",
    "message": "Authorization header missing",
    "details": {
      "header": "Authorization"
    }
  }
}
```

## Standard error envelope

All non-2xx SDK-facing HTTP failures use this JSON shape:

```json
{
  "error": {
    "code": "string",
    "message": "human-readable message",
    "details": {
      "optional": "context"
    }
  }
}
```

Used by:

- `POST /v1/execute`
- `POST /v1/execute/stream` before the stream is established
- `GET /v1/health` if a future HTTP-level failure is introduced

Common codes:

- `auth_required`
- `auth_invalid`
- `invalid_request`
- `request_too_large`
- `invalid_intent_contract`
- `invalid_profile`
- `validation_error`
- `execution_conflict`
- `too_many_requests`
- `streaming_unsupported`
- `receipt_signing_failed`

## IntentContract schema (frozen for SDK v1)

The execute request may include an optional `intent` object. When present, it must validate against the current server-side `IntentContract` JSON shape.
Unknown fields are rejected.

### Top-level fields

- `version` string, required, must be `"v1"`
- `execution_id` string, required inside `intent`
- `workflow_id` string, required
- `task_class` string, required
- `declared_purpose` string, required
- `language` string, required, must match request `lang`
- `backend_hint` string, optional, one of `"firecracker"`, `"gvisor"`
- `resource_scope` object, required
- `network_scope` object, required
- `process_scope` object, required
- `broker_scope` object, required
- `budgets` object, required
- `attributes` object of string-to-string, optional

### `resource_scope`

- `workspace_root` string, required, absolute path
- `read_paths` string array, required, absolute paths
- `write_paths` string array, required, absolute paths
- `deny_paths` string array, required, absolute paths
- `max_distinct_files` integer, required, must be `> 0`

### `network_scope`

- `allow_network` boolean, required
- `allowed_domains` string array, required
- `allowed_ips` string array, required, each must be a valid IP literal
- `max_dns_queries` integer, required, must be `>= 0`
- `max_outbound_conns` integer, required, must be `>= 0`

### `process_scope`

- `allowed_binaries` string array, required
- `allow_shell` boolean, required
- `allow_package_install` boolean, required
- `max_child_processes` integer, required, must be `>= 0`

### `broker_scope`

- `allowed_delegations` string array, required
- `allowed_domains` string array, optional
- `allowed_action_types` string array, optional
- `require_host_consent` boolean, required

### `budgets`

- `timeout_sec` integer, required, must be `> 0`
- `memory_mb` integer, required, must be `> 0`
- `cpu_quota` integer, required, must be `> 0`
- `stdout_bytes` integer, required, must be `> 0`

## `POST /v1/execute`

### Request JSON

```json
{
  "execution_id": "optional-uuid",
  "lang": "bash",
  "code": "echo hello",
  "timeout_ms": 10000,
  "profile": "default",
  "workspace_id": "optional-workspace",
  "intent": {
    "version": "v1",
    "execution_id": "11111111-1111-4111-8111-111111111111",
    "workflow_id": "wf_local_demo",
    "task_class": "demo",
    "declared_purpose": "run a local shell command",
    "language": "bash",
    "resource_scope": {
      "workspace_root": "/workspace",
      "read_paths": ["/workspace"],
      "write_paths": ["/workspace/out"],
      "deny_paths": [],
      "max_distinct_files": 4
    },
    "network_scope": {
      "allow_network": false,
      "allowed_domains": [],
      "allowed_ips": [],
      "max_dns_queries": 0,
      "max_outbound_conns": 0
    },
    "process_scope": {
      "allowed_binaries": ["bash"],
      "allow_shell": true,
      "allow_package_install": false,
      "max_child_processes": 2
    },
    "broker_scope": {
      "allowed_delegations": [],
      "require_host_consent": false
    },
    "budgets": {
      "timeout_sec": 10,
      "memory_mb": 128,
      "cpu_quota": 100,
      "stdout_bytes": 4096
    }
  }
}
```

### Request defaults

- `execution_id`
  - optional
  - server generates a UUID if omitted
- `timeout_ms`
  - optional
  - defaults to the loaded policy default when omitted or `0`
- `profile`
  - optional
  - defaults to the loaded policy default when omitted or empty
- `workspace_id`
  - optional
- `intent`
  - optional

Unknown request fields are rejected with `400 invalid_request`.

### Success response JSON

`200 OK`

```json
{
  "stdout": "hello\n",
  "stderr": "",
  "exit_code": 0,
  "exit_reason": "completed",
  "duration_ms": 1843,
  "execution_id": "11111111-1111-4111-8111-111111111111",
  "output_truncated": false,
  "proof_dir": "/tmp/aegis/proofs/11111111-1111-4111-8111-111111111111",
  "receipt_path": "/tmp/aegis/proofs/11111111-1111-4111-8111-111111111111/receipt.dsse.json",
  "receipt_public_key_path": "/tmp/aegis/proofs/11111111-1111-4111-8111-111111111111/receipt.pub",
  "receipt_summary_path": "/tmp/aegis/proofs/11111111-1111-4111-8111-111111111111/receipt.summary.txt"
}
```

### Execute response semantics

- `exit_code` / `exit_reason` describe guest process completion.
- `error` is omitted on successful completed executions.
- Non-zero `exit_code` is still a normal `200 OK` execute response.
- Some runtime failures also surface as `200 OK` execute responses with `error` populated and `execution_id` set, because the server already accepted and tracked the execution attempt.
- `proof_dir` and receipt paths are host-local filesystem paths intended for local tooling and the local SDK.

## `POST /v1/execute/stream`

### Request JSON

Same JSON body as `POST /v1/execute`.

### Initial HTTP response

If request validation fails **before** the stream starts, the server returns the standard JSON error envelope.

If streaming starts successfully, the response uses:

```http
Content-Type: text/event-stream
X-Execution-ID: <execution_id>
```

### SSE event shapes

The server emits `data: <json>` frames containing `models.GuestChunk` objects.
Relevant `type` values for SDK v1:

- `stdout`
- `stderr`
- `proof`
- `error`
- `done`

`proof` includes `proof_dir`, `receipt_path`, `receipt_public_key_path`, and `receipt_summary_path`.
`done` includes final `exit_code`, `reason`, and `duration_ms`.

Stream-time runtime failures surface as `type: "error"` events, not as the JSON error envelope.

## `GET /v1/health`

### Response JSON

`200 OK`

```json
{
  "status": "ok",
  "worker_slots_available": 5,
  "worker_slots_total": 5
}
```

## Curl examples

### Local dev health

```bash
curl -sS http://localhost:8080/v1/health
```

### Local dev synchronous execute

```bash
curl -sS -X POST http://localhost:8080/v1/execute   -H 'Content-Type: application/json'   -d '{"lang":"bash","code":"echo sdk-contract","timeout_ms":10000}'
```

### Authenticated synchronous execute

```bash
AUTH_HEADER='Authorization: Bearer <token>'
curl -sS -X POST http://localhost:8080/v1/execute   -H 'Content-Type: application/json'   -H "$AUTH_HEADER"   -d '{"lang":"bash","code":"echo sdk-contract","timeout_ms":10000}'
```

### Streaming execute

```bash
curl -N -sS -X POST http://localhost:8080/v1/execute/stream   -H 'Content-Type: application/json'   -d '{"lang":"bash","code":"echo sdk-stream","timeout_ms":10000}'
```

## Frozen vs not frozen summary

Frozen for Python SDK v1:

- endpoint list in this document
- request JSON fields for `POST /v1/execute` and `POST /v1/execute/stream`
- `IntentContract` JSON field names and validation rules described here
- `Authorization: Bearer <token>` when API auth is enabled
- standard JSON error envelope for non-2xx SDK-facing failures
- synchronous execute as the primary SDK path

Not frozen yet:

- telemetry/event stream APIs outside `POST /v1/execute/stream`
- workspace lifecycle endpoints
- stats/metrics endpoints
- any future async polling or receipt-download endpoint
- proof bundle internal file contents beyond the existing local receipt tooling contract
