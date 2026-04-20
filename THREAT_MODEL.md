# Threat Model

Aegis exists to reduce blast radius for untrusted AI-generated code. It is a containment boundary, not a trust system for the rest of the stack.

## What Aegis Protects

### Host integrity

Aegis is designed to keep generated code off the host:
- code runs in a Firecracker microVM instead of a host process
- guest execution uses a dedicated guest-runner, not the host control plane
- per-run scratch state is torn down after execution
- host-side cgroups constrain CPU, memory, PID, and swap policy

### Resource abuse

Aegis is meant to contain common failure modes:
- infinite loops
- fork bombs
- process explosions
- oversized stdout / stderr
- memory pressure
- hung executions that would otherwise sit forever

This is where the system is strongest today. It is built to survive bad runs, not trust them.

### Network egress

Default behavior is conservative:
- no-network mode gives the guest no NIC
- egress-allowlist mode intercepts DNS only when needed and installs narrow outbound rules only for explicitly allowed destinations
- if an intent supplies any allowlist field, the omitted allowlist dimension is empty for that execution rather than inherited from baseline
- FQDN allowlist answers are resolved once at execution start and pinned for the life of the execution
- loopback `127.0.0.0/8` remains allowed inside the guest for brokered outbound and is recorded in the runtime receipt allowlist

The goal is not safe arbitrary internet access. The goal is explicit network posture: no network by default, or a narrow allowlist flow when a policy declares domains or CIDRs.

### Residual state

Aegis is designed to prevent accidental host residue:
- scratch state is per execution
- TAP state is per execution
- cgroup state is per execution
- sockets are per execution
- containment receipts are emitted after cleanup state is known

Persistent workspaces are explicit named objects, not accidental leftovers.

## What Aegis Does Not Protect

### Prompting and tool judgment

Aegis does not make the model correct. If an agent chooses to run the wrong code, Aegis only limits where that code runs.

### Supply-chain trust

Aegis does not prove the host, rootfs, build pipeline, or dependencies are fully trustworthy. Recent checksum verification improves the install story, but it is not a full supply-chain security program.

### IAM and secret misuse outside the sandbox

Aegis does not protect credentials that are exposed outside the execution path. If another component can misuse a token directly, Aegis is not the thing that stops it.

### Hypervisor or kernel escape

Aegis raises the bar compared to host execution, but it does not claim a formal guarantee against Firecracker, KVM, virtio, or kernel escape bugs.

## Current Enforced Boundaries

Current host/guest protections:
- Firecracker microVM boundary
- KVM-backed virtualization
- host cgroups v2
- no-network or `egress_allowlist` network mode
- host/guest transport over Firecracker's Unix-socket vsock proxy
- deterministic teardown with cleanup reflected in the final receipt

Recent hardening reflected in the current repo:
- workspace path traversal / file clobber fix
- Firecracker environment inheritance tightening
- SSE wait abuse reduction
- guest-control vsock size cap
- install-time checksum verification

## Public Demo Claims That Are Reasonable

Reasonable claims:
- Aegis runs untrusted code inside disposable Firecracker microVMs
- the proving ground is wired to a live backend
- DNS allow/deny telemetry is real
- selective egress rule installation is real
- PID-cap containment is real
- output truncation is real
- blocked outbound connect is real
- containment receipts and in-memory stats are real

Claims that should stay conservative:
- Memory Pressure is a safe-failure demo under pressure, not a kernel OOM-kill proof
- compute profiles are real at the VM-shape level, not full resource envelopes
- snapshots and cold-boot optimization are future work, not shipped behavior

## Threat Model for the Proving Ground

The proving ground deliberately accepts hostile or sloppy payloads from strangers. That makes the trust boundary real:
- visitors can trigger live executions
- the UI subscribes to live telemetry before execution starts
- the receipt reflects real cleanup state

This is useful because it forces the project to prove containment behavior in public, not just in private scripts.

It is also why the docs should stay sober. The project is strongest when it says exactly what it proves today and nothing more.
