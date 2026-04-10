# HTTP API

This document describes the current public HTTP surface exposed by `aegis serve`.

OpenAPI description: [openapi.json](openapi.json)

## Base URL

Default local base URL:

```text
http://localhost:8080
```

## Authentication

Execution endpoints are protected with `Authorization: Bearer <token>` **only when** the server is started with `AEGIS_API_KEY`.

Health remains unauthenticated so local tooling can probe server readiness without embedding credentials.

## Error model

Structured JSON errors use this envelope:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "invalid request body",
    "details": {
      "cause": "unexpected EOF"
    }
  }
}
```

Important operational detail:

- `POST /v1/execute` may still return `200 OK` for an accepted execution whose runtime outcome is unsuccessful. Runtime failures are represented in the execution result body, not always as transport-level HTTP errors.

## Endpoints

### `GET /v1/health`

Returns lightweight process health and worker-slot availability.

Example response:

```json
{
  "status": "ok",
  "worker_slots_available": 5,
  "worker_slots_total": 5,
  "warm_pool": {
    "enabled": true,
    "configured_size": 1,
    "available": 1,
    "initializing": 0,
    "max_age_seconds": 300,
    "warm_claims": 4,
    "cold_fallbacks": 1,
    "claim_errors": 0,
    "recycled_expired": 0
  }
}
```

Compatibility alias: `GET /health`

### `GET /ready`

Returns readiness posture, including database reachability and worker availability.

Returns:

- `200 OK` when ready
- `503 Service Unavailable` when not ready

Example response:

```json
{
  "status": "ready",
  "db_ok": true,
  "worker_slots_available": 5,
  "worker_slots_total": 5,
  "warm_pool": {
    "enabled": true,
    "configured_size": 1,
    "available": 1,
    "initializing": 0,
    "max_age_seconds": 300,
    "warm_claims": 4,
    "cold_fallbacks": 1,
    "claim_errors": 0,
    "recycled_expired": 0
  }
}
```

### `POST /v1/execute`

Runs code in a Firecracker-backed execution path and returns a structured result, plus proof metadata when receipt generation succeeds.

Request body:

```json
{
  "execution_id": "optional-uuid",
  "lang": "bash",
  "code": "echo hello",
  "timeout_ms": 10000,
  "profile": "nano",
  "workspace_id": "",
  "intent": {
    "version": "v1",
    "...": "optional intent contract"
  }
}
```

Key behaviors:

- request bodies are strictly decoded; unknown fields are rejected
- `execution_id` is optional but must be a valid UUID if provided
- `timeout_ms=0` means “use the policy default”
- `profile` is optional and defaults to the policy default
- proof bundle fields are present only when receipt generation succeeds

Successful runtime example:

```json
{
  "stdout": "hello\n",
  "stderr": "",
  "exit_code": 0,
  "exit_reason": "completed",
  "duration_ms": 12,
  "execution_id": "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b",
  "proof_dir": "/tmp/aegis/proofs/30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b",
  "receipt_path": "/tmp/aegis/proofs/30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b/receipt.dsse.json",
  "receipt_public_key_path": "/tmp/aegis/proofs/30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b/receipt.pub",
  "receipt_summary_path": "/tmp/aegis/proofs/30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b/receipt.summary.txt"
}
```

Accepted-but-unsuccessful runtime example:

```json
{
  "stdout": "",
  "stderr": "",
  "exit_code": 0,
  "exit_reason": "sandbox_error",
  "duration_ms": 10,
  "execution_id": "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b",
  "error": "timeout"
}
```

Common HTTP errors:

- `400 invalid_request`
- `400 invalid_profile`
- `400 invalid_intent_contract`
- `400 validation_error`
- `401 auth_required`
- `401 auth_invalid`
- `409 execution_conflict`
- `413 request_too_large`
- `429 too_many_requests`
- `500 receipt_signing_failed`

### `POST /v1/execute/stream`

Runs the same execution path but returns Server-Sent Events.

Response content type:

```text
text/event-stream
```

Representative event stream:

```text
data: {"type":"stdout","chunk":"hello\n"}

data: {"type":"proof","execution_id":"30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b","proof_dir":"/tmp/aegis/proofs/30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b","receipt_path":"/tmp/aegis/proofs/30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b/receipt.dsse.json","receipt_public_key_path":"/tmp/aegis/proofs/30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b/receipt.pub","receipt_summary_path":"/tmp/aegis/proofs/30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b/receipt.summary.txt","artifact_count":2,"divergence_verdict":"allow"}

data: {"type":"done","exit_code":0,"reason":"completed","duration_ms":12}
```

The request body matches `POST /v1/execute`.

### `GET /v1/events/{exec_id}`

Streams telemetry events for a specific execution ID.

Behavior:

- waits briefly for a matching execution bus to appear
- returns `404` if the execution does not appear within the wait window
- returns `429` when too many pending telemetry subscribers are already waiting

Representative event:

```text
data: {"exec_id":"30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b","kind":"vm.boot.start","data":{"phase":"boot"}}
```

### `GET /v1/stats`

Returns aggregate in-memory counters derived from completed receipts.

Example response:

```json
{
  "total_executions": 7,
  "total_completed": 5,
  "total_contained": 2,
  "dns_queries_total": 3,
  "dns_queries_allowed": 2,
  "dns_queries_denied": 1,
  "iptables_rules_added": 2,
  "clean_teardowns": 7,
  "escapes": 0
}
```

### `DELETE /v1/workspaces/{id}`

Deletes a persistent workspace by ID.

Protected by the same optional bearer auth as execution endpoints.

Successful response:

```json
{
  "status": "deleted",
  "workspace_id": "workspace-123"
}
```

Common errors:

- `400 invalid_workspace_id`
- `404 workspace_not_found`
- `500 workspace_delete_failed`

### `GET /metrics`

Prometheus-style metrics for operator observability.

This is an operational endpoint, not a proof or SDK endpoint.

## What is not exposed over HTTP

Receipt verification is not currently a first-class HTTP endpoint.

Use one of these instead:

- `aegis receipt verify`
- Python SDK `client.verify_receipt(...)`
- TypeScript SDK `client.verifyReceipt(...)`
- MCP `aegis_verify`
