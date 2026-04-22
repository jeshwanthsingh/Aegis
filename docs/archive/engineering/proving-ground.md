# Aegis Proving Ground

The proving ground is the live demo surface for Aegis. It runs real payloads in Firecracker microVMs, streams telemetry over SSE, and renders the final containment receipt and aggregate stats after teardown.

It is meant to answer a simple question quickly: does the sandbox actually do what it says when you hand it hostile or sloppy code?

## How the UI Works

The proving-ground flow is intentionally simple:

1. The UI selects a preset or accepts edited code.
2. The browser creates or reuses an `execution_id`.
3. The browser opens `GET /v1/events/{exec_id}` before execution starts.
4. The browser submits `POST /v1/execute` with the same `execution_id`.
5. The orchestrator boots a VM, runs the payload, emits telemetry, tears the VM down, and emits a final containment receipt.
6. The UI renders:
   - live telemetry events
   - stdout / stderr
   - the containment receipt
   - `/v1/stats`

This is a live system, not a replay.

## Presets

### Allowed DNS
What it demonstrates:
- allowlisted DNS resolution works
- resolved IPs trigger selective outbound rule installation
- the receipt network summary reflects allowed DNS and rule adds

What it does not prove:
- general outbound internet access
- arbitrary egress control beyond the current allowlist flow

### Denied DNS
What it demonstrates:
- non-allowlisted domains are denied at the DNS decision point
- no allow rules are installed for denied domains
- the receipt network summary reflects denied DNS cleanly

What it does not prove:
- full firewall coverage for every possible guest behavior

### Fork Bomb
What it demonstrates:
- guest process growth hits the configured PID ceiling
- the run exits with `pids_limit`
- teardown remains clean

What it does not prove:
- broader kernel stability claims
- an exhaustive process-isolation story beyond the enforced PID cap

### Memory Pressure
What it demonstrates:
- code can fail safely under memory pressure
- the run still tears down cleanly

What it does not prove:
- a kernel OOM kill
- a cgroup OOM event
- a stronger memory-isolation claim than what has been directly observed

Use conservative language for this preset. It is a safe-failure demo under pressure, not an OOM-kill showcase.

### Blocked Outbound Connect
What it demonstrates:
- a short outbound socket attempt is blocked
- the run returns a crisp user-visible result

What it does not prove:
- a general outbound-blocking guarantee for every technique
- a broader outbound policy story than the blocked-connect path being shown

### Huge Stdout
What it demonstrates:
- oversized stdout is truncated intentionally
- `output_truncated` is reflected in the receipt
- the run still completes and tears down cleanly

What it does not prove:
- full-output preservation
- unbounded streaming

## Strongest Demo Flows

If you only have time for a short walkthrough, use these:
- `Allowed DNS`
- `Denied DNS`
- `Fork Bomb`
- `Huge Stdout`
- `Blocked Outbound Connect`

These are the sharpest demonstrations of real policy decisions, containment, and receipts on the current stack.

`Memory Pressure` is still worth showing, but only with conservative framing.

## Telemetry Stream

The event stream is meant to show the control-plane path, not just final output.

Common event categories:
- `vm.boot.start`
  - VM boot requested
- `vm.boot.ready`
  - host is connected to the guest execution path
- `cgroup.configured`
  - host-side cgroup values applied
- `dns.query`
  - DNS allow/deny decision
- `net.rule.add`
  - selective outbound allow rule inserted
- `exec.exit`
  - guest process exit observed
- `cleanup.start`
  - teardown begins
- `cleanup.done`
  - teardown finished
- `containment.receipt`
  - final receipt emitted
- `output.truncated`
  - output hit the response cap
- `guest.proc.sample`
  - guest PID telemetry used by the Fork Bomb story

The stream is useful for:
- watching boot and teardown timing
- seeing network policy decisions directly
- distinguishing execution failure from cleanup failure
- correlating the final receipt with the live path that produced it

## Containment Receipt

The containment receipt is the final post-teardown summary. It is emitted after cleanup state is known.

Receipt sections:
- `policy`
  - policy version
  - active compute profile
  - network mode
  - cgroup values
- `network`
  - DNS totals
  - allowed vs denied counts
  - rule-add count
- `exit`
  - exit code
  - terminal reason
  - `output_truncated`
- `cleanup`
  - whether TAP, cgroup, scratch, and socket state were removed
- `verdict`
  - final high-level classification

Important terminal reasons on the current stack:
- `completed`
- `pids_limit`
- `timeout`
- `sandbox_error`

The receipt is the right place to answer:
- did containment hold
- did teardown finish cleanly
- what policy was in effect
- what the network path actually did

## `/v1/stats`

`GET /v1/stats` returns in-memory aggregate counters derived from completed receipts.

It is useful for:
- showing that the proving ground is live and accumulating executions
- summarizing containment and teardown outcomes
- surfacing counters like clean teardowns and denied DNS events

It is not:
- a long-term analytics store
- a full historical audit system

Those roles belong elsewhere.

## Compute Profiles in the Proving Ground

Current built-ins:
- `nano` -> 1 vCPU / 128 MiB
- `standard` -> 2 vCPU / 512 MiB
- `crunch` -> 4 vCPU / 2048 MiB

Current proving-ground reality:
- the API supports the optional `profile` field
- the current proving-ground UI does not expose profile selection directly
- if no profile is supplied, the API defaults to `nano`
- the receipt shows the active profile

Truthfulness note:
- profiles currently change Firecracker VM shape
- profiles do not yet change host cgroup policy

So they are real, but they are not full resource envelopes.

Recommended demo default today:
- `nano`

Why:
- it is the current default
- it is the fastest measured profile
- it aligns with the current public demo story

## Reading the Demo Honestly

Good claims:
- Aegis runs untrusted code in disposable Firecracker microVMs
- the proving ground is wired to a live backend
- DNS allow/deny is real
- selective egress rule installation is real
- PID cap containment is real
- output truncation is real
- blocked outbound connect is real
- receipts and stats are real

Claims to avoid:
- Memory Pressure proves a kernel or cgroup OOM kill
- compute profiles already represent full runtime envelopes
- snapshots or optimized cold starts are already implemented

## Recommended Screenshots

Capture these from the live proving ground:
- idle proving-ground state
- Allowed DNS with `dns.query allow` and `net.rule.add`
- Denied DNS with a clean denial
- Fork Bomb with `pids_limit`
- Huge Stdout with `output_truncated`
- Blocked Outbound Connect with the visible blocked result
