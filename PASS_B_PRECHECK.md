# PASS B Precheck

## Assumption 1

Confirmed. The current code already emits telemetry for all three blocked-egress shapes Pass B needs to summarize.

- Public IP outside allowlist:
  - guest/runtime `net.connect` events are normalized and emitted on the bus (`internal/executor/runtime_events.go:101-120`)
  - denied connect attempts become `policy.point.decision` events (`internal/executor/runtime_events.go:115-120`)
  - `evaluateConnect()` denies external targets outside the effective allowlist with reason `destination is outside network allowlists` (`internal/policy/evaluator/evaluator.go:164-190`)
  - denied `net.connect` events are also converted into governed-action telemetry (`internal/executor/runtime_events.go:119-120`, `internal/executor/runtime_events.go:206-214`, `internal/governance/governance.go:250-301`)

- DNS query for a non-allowlisted name:
  - the DNS interceptor emits `dns.query` telemetry with `action: "deny"` and `reason: "not in allowlist"` (`internal/executor/lifecycle.go:788-813`)
  - this is existing host-side telemetry; no new event kind is needed

- TCP connect to RFC1918 / metadata:
  - guest/runtime `net.connect` still emits exactly as above (`internal/executor/runtime_events.go:101-120`)
  - `evaluateConnect()` hard-denies RFC1918 / metadata destinations with reason `destination is blocked by runtime network baseline` (`internal/policy/evaluator/evaluator.go:181-189`)
  - that denied `net.connect` is also converted into governed-action telemetry (`internal/executor/runtime_events.go:119-120`, `internal/governance/governance.go:250-301`)

Conclusion: all three beat types already have denial telemetry that Pass B can summarize.

## Assumption 2

Confirmed. The receipt builder already receives the full execution telemetry stream via `bus.Drain()`.

- `emitSignedReceipt()` drains the execution bus and passes the result into `receipt.BuildSignedReceipt(...)` as `TelemetryEvents: events` (`internal/api/handler.go:1331-1360`)
- `buildPredicate()` summarizes `input.TelemetryEvents` through `summarizeTelemetry(...)`, the same path that already computes broker and governed-action receipt sections (`internal/receipt/builder.go:48-80`)

Conclusion: `runtime.network.blocked_egress` can be computed in the receipt builder from existing telemetry without adding new telemetry kinds.

## Gate verdict

Proceed with Pass B implementation.
