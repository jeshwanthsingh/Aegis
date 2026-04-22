# Cedar Compilation Target

Aegis v2 exposes JSON contracts externally and compiles them into Cedar evaluation inputs internally. The JSON schema is the product API. Cedar is the deterministic policy target used by the orchestrator.

## Mapping

| IntentContract field | Cedar concept | Notes |
| --- | --- | --- |
| `execution_id`, `workflow_id` | principal | Principal represents the execution context. Workflow identity and selected attributes compile into principal attributes. |
| event `type` | action | Aegis normalizes runtime events to a fixed action set such as `read`, `write`, `delete`, `exec`, `connect`, and `broker`. |
| path, binary, domain, broker delegation | resource | Resource type depends on the event: file path, binary name, domain/IP, or delegation target. |
| `task_class`, `declared_purpose`, backend, budgets, booleans, optional attributes | context | Context carries evaluation inputs that are not stable entity identity. |

## Compilation Rules

- `resource_scope` compiles into file and workspace resource attributes.
- `network_scope` compiles into network resource attributes and context limits.
- `process_scope` compiles into executable resource attributes plus context flags such as `allow_shell`.
- `broker_scope` compiles into broker delegation resource attributes.
- `budgets` compile into context values for point checks. Budget accounting itself remains outside Cedar.

## Example Policies

```cedar
permit(
  principal,
  action == Action::"read",
  resource
)
when {
  resource in principal.read_paths &&
  !(resource in principal.deny_paths)
};
```

```cedar
forbid(
  principal,
  action == Action::"connect",
  resource
)
unless {
  context.allow_network &&
  resource.domain in principal.allowed_domains
};
```

## What Stays Outside Cedar

These concerns remain orchestrator state logic, not direct Cedar policy:

- sequence-based divergence rules
- process tree fan-out tracking
- distinct-file counters
- DNS and connection count accumulation
- telemetry flood detection and drop accounting
- teardown, kill, and receipt assembly

Cedar answers point-in-time authorization questions. The orchestrator owns temporal state, aggregation, and enforcement side effects.
