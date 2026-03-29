# Aegis Known Issues

## Current Runtime Limitations
- Cold boot time is still materially high in WSL2 because startup includes a full-copy scratch image workflow plus guest bootstrap overhead.
- Network exfiltration tests are currently contained by timeout behavior rather than an immediate explicit unreachable error.
- Context timeout does not fully interrupt the earliest boot path and becomes effective later in the VM lifecycle.
- Temporary DNS packet/response logging remains enabled in the interceptor for investigation visibility and should be removed once CI confidence is established.
- `/ready` currently reports not-ready when worker slots are fully saturated, which is operationally useful but should be documented for any external load balancer expectations.

## Investigation Targets
- Re-test the `crunch` profile with the current timeout and validation scripts on WSL2 and Linux CI.
- Explain the nonzero exit on the successful persistent workspace read path.
- Thread cancellation context deeper into VM creation and boot logic.
- Re-run benchmarks after any storage or boot-path changes instead of relying on old numbers.
