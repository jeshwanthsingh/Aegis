# Threat Model

Aegis exists to run untrusted generated code in a smaller blast radius than the host machine.

## What Aegis Is Trying To Protect

### Host integrity
Aegis is meant to stop generated code from running with direct access to the host process table, host filesystem, host network stack, and host credentials. Code runs inside a disposable Firecracker microVM, not on the host OS.

### Resource abuse
Aegis is meant to contain the obvious failure modes of untrusted execution:
- infinite loops
- fork bombs
- process explosions
- memory abuse
- huge stdout/stderr floods
- hung executions that never return on their own

The control plane applies timeouts, cgroup limits, and deterministic teardown so one bad execution does not permanently poison the host.

### Network exfiltration
In the default isolated mode, the guest gets no NIC at all. In allowlist mode, DNS is intercepted per execution and only explicitly allowed destinations should resolve. The goal is not “safe internet access.” The goal is “no ambient egress, and narrowly scoped exceptions when absolutely required.”

### Persistence and residue
Aegis is meant to prevent one execution from leaving durable host state behind. Scratch disks, TAP devices, sockets, and cgroups are created per execution and then torn down. Persistent workspaces are explicit, named storage objects, not accidental leftovers.

## What Aegis Does Not Protect Against

### Prompt injection and agent misbehavior
Aegis does not fix upstream agent judgment. If the model decides to run the wrong code, Aegis only limits where that code runs. It does not make the decision safe or correct.

### Supply chain compromise
Aegis does not prove the guest image, host binaries, downloaded dependencies, or the orchestrator build pipeline are trustworthy. If your rootfs, Firecracker binary, package mirror, or build environment is compromised, Aegis inherits that compromise.

### IAM and secret misuse outside the sandbox
Aegis does not secure GitHub tokens, cloud keys, Slack tokens, or email credentials that live outside the execution path. If another part of the system can misuse those credentials directly, Aegis is not the control that stops it.

### Model-layer policy failures
Aegis does not replace guardrails, review, allow/deny policy at the prompt/tool layer, or human approval. It is a containment boundary, not a behavioral guarantee.

### Kernel or hypervisor escape
Aegis meaningfully raises the bar compared to local execution, but it is not a formal guarantee against Firecracker, KVM, kernel, or virtio escape bugs. If you need that claim, you need a much deeper security program than this repo currently provides.

## Operational Reality
Aegis is strongest against the boring, common failures that actually happen in agent systems: runaway code, host contamination, accidental egress, and poor teardown hygiene. It is not a silver bullet. If you market it like one, you are lying to yourself.
