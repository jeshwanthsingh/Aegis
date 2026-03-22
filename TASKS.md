# Aegis — Task Roadmap

## Project Positioning (do not deviate from this)

**One-liner:**
A self-hostable Firecracker-backed execution plane for OpenClaw that isolates untrusted AI-generated code with cgroup v2 limits, no-network defaults, strict teardown, measurable benchmarks, and a drop-in skill.

**What Aegis is:**
- The code-execution isolation layer for OpenClaw agents
- Self-hostable, local-first, open source
- Complements OpenClaw (agent runtime) and NeMo Guardrails (policy/prompt rails)

**What Aegis is NOT:**
- A replacement for NeMo Guardrails
- A solution for prompt injection at the LLM level
- A tool permission or credentials manager
- An end-to-end agent security platform

---

## Phase 1 — Aegis v1.5 (production-ish) 
Status: in progress

- [ ] Worker pool — 5 concurrent VM slots, bounded queue, reject above capacity
- [ ] API key auth — Bearer token middleware, configured via AEGIS_API_KEY env var
- [ ] Rate limiting — token bucket, 10 requests/minute per key default
- [ ] Fix rootfs naming — replace "Alpine Linux" with "Ubuntu 22.04 (Firecracker quickstart base)" everywhere
- [ ] Systemd service file — auto-start on boot, restart on crash
- [ ] install.sh — zero to running in under 10 minutes on bare Linux
- [ ] Stage benchmarks — measure image_prep / boot / guest_ready / execute / teardown separately
- [ ] README rewrite — threat model, non-goals, API contract, state machine, benchmark methodology

Already done in v1:
- [x] Firecracker microVM boot via API
- [x] virtio-vsock transport layer
- [x] Guest runner (static Go binary in rootfs)
- [x] cgroup v2: memory.max, memory.high, pids.max, cpu.max, memory.swap.max
- [x] No network interfaces (deny-all default)
- [x] Hard timeout + SIGKILL
- [x] Deterministic teardown (scratch + sockets + cgroup)
- [x] Postgres audit log
- [x] Output caps (stdout/stderr truncation)
- [x] Execution state machine (booting/running/completed/timed_out/oom_killed/sandbox_error)
- [x] Startup reconciliation (orphan VM cleanup on boot)
- [x] Demo tests: fork bomb / exfiltration / host escape — all passing

---

## Phase 2 — OpenClaw Skill
Status: not started

- [ ] Write aegis-exec skill (JavaScript, ~80 lines)
      Routes OpenClaw code execution requests to Aegis POST /v1/execute
      Handles auth header, timeout, result formatting back to OpenClaw
- [ ] Test skill end-to-end with local OpenClaw install
- [ ] Write skill README: install in one command, what it does, what it doesn't do
- [ ] Publish to ClawHub
- [ ] Write integration guide: "Using OpenClaw + NeMo Guardrails + Aegis"
      Diagram showing three layers and what each covers

---

## Phase 3 — GitHub IAM Proxy MVP
Status: not started

- [ ] Proxy server (Go) that intercepts GitHub API calls
- [ ] Action classifier: read / write / destructive
      Read: GET /repos/*, GET /issues/*, GET /pulls/*
      Write: POST /issues, POST /pulls, PATCH non-destructive
      Destructive: DELETE /repos/*, archive, transfer, permission changes
- [ ] Policy: reads pass through, writes log, destructive require approval
- [ ] Approval mechanism: webhook POST to configured URL (simple, no mobile app)
- [ ] Short-lived token: generate scoped GitHub token per approved action, expire after 30s
- [ ] Agent uses proxy URL instead of api.github.com directly
- [ ] No long-lived GitHub key inside the agent ever
- [ ] README: threat model, what routes are classified how, how to configure

---

## Positioning per project

| Project | What it secures | What it does NOT secure |
|---------|----------------|------------------------|
| Aegis | Code execution lane | Agent reasoning, integrations, secrets |
| NeMo Guardrails | Prompt/output policy | Code execution, credentials |
| GitHub IAM Proxy | GitHub tool credentials | Other integrations, code execution |

---

## The full stack (when all three exist)

```
User message
    ↓
OpenClaw (agent runtime + 100+ tools)
    ↓
NeMo Guardrails (semantic boundary)
  - input rails: detect prompt injection
  - output rails: scan for secrets
  - Colang policies: block unauthorized tool use
    ↓
LLM (Claude / OpenAI)
    ↓
OpenClaw triggers code execution
    ↓
Aegis POST /v1/execute (compute boundary)
  - Firecracker microVM
  - no network
  - cgroup v2 limits
  - hard timeout + teardown
    ↓
OpenClaw triggers GitHub tool
    ↓
GitHub IAM Proxy (credential boundary)
  - classify action
  - block destructive by default
  - require approval for high-risk
  - JIT scoped token
```

---

## Hard rules (never violate)

- Never claim Aegis stops prompt injection
- Never claim Aegis secures agent integrations
- Never call it a "grid" until multi-node scheduling exists
- Never quote sub-100ms boot without snapshot restore implemented
- Always label benchmarks with hardware + clone method
- Scope claims to what is actually built
