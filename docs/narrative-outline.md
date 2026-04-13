# Narrative Outline

This is an internal packaging outline, not public marketing copy.

## Product thesis

Aegis is not just a sandbox. It is an execution evidence system for running untrusted code under a real isolation boundary and proving what the runtime allowed, denied, and observed.

## Market gap

Most execution products make you choose one of these:

- convenience without a strong isolation boundary
- isolation without usable proof artifacts
- logs without a clean policy story

Aegis is aimed at the gap where people need all three:

- hardware-isolated execution
- policy-governed external action
- post-run verification artifacts

## Canonical product story

The default story should stay narrow:

1. an allowed governed action succeeds
2. a denied direct egress attempt is blocked
3. receipts verify both outcomes afterward

That is the shortest honest loop that makes Aegis legible.

## Strong claims we can make honestly

- Aegis runs untrusted code in Firecracker microVMs.
- Aegis exposes a policy-governed path for allowed external action.
- Aegis blocks direct egress on the denied path shown in the canonical demo.
- Aegis emits proof bundles and signed receipts that can be verified after execution.
- The runtime, proof pipeline, and local operator flow are real in this repo state.

## Claims we must not make

- package install alone gives a full runtime bring-up
- Aegis is already a hosted multi-tenant platform
- warm execution covers every request shape
- workspace continuity is the main first story
- receipts replace trust assumptions with host attestation
- HSM or KMS-backed signing custody exists today

## Why the canonical demo works

- It shows one positive outcome and one negative outcome.
- It keeps the trust boundary visible.
- It ends with verification instead of vibes.
- A new person can repeat it back in one sentence.

## Secondary stories, not default

- warm-vs-cold improvement
- persistent workspace continuity
- proving-ground presets
- broader hardening and fault-matrix coverage

These are real assets, but they should support the main story instead of replacing it.

## Later distribution angles

### GitHub positioning

Lead with execution evidence, not generic sandboxing. The canonical demo should be the first serious proof path after basic onboarding.

### Article or blog

Use the thesis: most systems show logs or isolation; Aegis shows governed execution plus verification. Build the piece around the allow, deny, verify sequence.

### LinkedIn

Keep it legible and concrete: untrusted code, governed action, blocked direct egress, verified receipts. No protocol rabbit holes.

### Reddit / Hacker News

Lead with the technical claim and the runnable proof path. Expect scrutiny on honesty, trust boundaries, and what is not yet claimed.

## Discipline for later distribution work

- keep the default story short
- show the command early
- separate onboarding from proof
- separate proof from broader platform ambitions
- never let optional capabilities dilute the main explanation
