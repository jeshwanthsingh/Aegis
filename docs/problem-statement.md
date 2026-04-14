# Problem Statement

Aegis lets internal coding agents run code without giving them your machine, and proves what they tried to do.

Today that proof is a signed host-side execution record tied to a local proof bundle. It is useful, but it is not host attestation.

## The problem

Teams want internal coding agents to run builds, tests, scripts, and repo-local automation against real codebases. The problem is not just "can the agent execute code." The problem is "can the agent execute code without getting a normal workstation or CI runner, and can the team later show what the agent attempted."

For a security or platform owner, the sharp concern is direct exfiltration:

- a coding agent gets access to source code, environment, or generated secrets
- it runs arbitrary code to complete a task
- it can also try to open its own network path and send that material somewhere else

## Who has this problem

- platform teams enabling internal coding agents on real repos
- security teams asked to approve agent execution on developer-adjacent infrastructure
- engineering teams that want agent automation but do not want to hand agents raw host access

## Why "just sandbox it" is insufficient

Generic sandboxing solves only part of the problem.

- isolation alone does not tell you whether the agent attempted a denied action
- generic logs are not the same as a signed execution record tied to one run
- a hosted sandbox can move the trust boundary away from the team operating the workflow
- internal coding-agent rollouts usually need self-hosted control over policy, runtime, and proof artifacts

For this wedge, the buyer usually needs all three:

- code runs away from the host
- direct egress is denied by default
- the run ends with a verifiable receipt, not just console logs

## What the canonical exfil demo proves

The repo-native demo shows the same payload in two conditions.

- without Aegis, the local receiver prints `RECEIVED: TOP_SECRET=demo-key-123`
- with Aegis, the same egress attempt is denied and verification prints `verification=verified`, `denial_marker=direct_egress_denied`, and `denial_rule_id=governance.direct_egress_disabled`

That proves a narrow but important point: Aegis can run untrusted coding-agent payloads in a Firecracker microVM, deny direct egress by default, and produce a signed record of the denied action and the execution that triggered it.

## Why self-hosted execution control plus receipts matters

Self-hosted control matters because the team evaluating the pilot can operate the runtime, policy surface, proof bundles, and verifier on its own infrastructure.

Receipts matter because they let the operator answer the question a security reviewer will ask after the fact:

"What did the agent try to do, what was denied, and what signed record do you have for that run?"

For the trust boundary and limits of that proof, use [trust-model.md](trust-model.md) and [receipt-schema.md](receipt-schema.md).
