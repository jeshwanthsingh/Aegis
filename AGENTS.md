# Aegis Contract

## Repo Map

- `AGENTS.md`: repo contract and review bar.
- `.agents/skills/`: Aegis-specific review and debug skills.
- `.artifacts/graphify/`: generated graph artifacts. Do not commit.
- Runtime, API, and demo code may be added later. Treat this file as the contract for those areas.

## Critical Commands

- `git status --short`
- `git diff --stat`
- `rg --files`
- `rg -n "firecracker|rootfs|vsock|cgroup|teardown|audit|egress" .`
- Run the narrowest existing test or check for the touched area. Do not invent new repo workflows.

## Sensitive Areas

- Runtime containment and sandbox setup.
- Rootfs lifecycle and cleanup.
- Vsock and host/guest communication.
- Cgroup limits, process teardown, and orphan cleanup.
- Egress controls, audit logs, and artifact generation.

## Invariants

- Containment stays explicit and default-deny where intended.
- Teardown is safe to retry and leaves no leaked processes or mounts.
- Cancellation does not skip cleanup.
- Audit output is attributable, durable enough for review, and not silently truncated.
- Demo paths must not hide important failure behavior.

## Review Priorities

- Trust boundaries before convenience.
- Cleanup ordering before happy-path speed.
- Regressions in teardown, cancellation, and logging.
- Claims in demos must match actual system behavior.

## Done

- The smallest safe change is in place.
- Root cause is addressed, not masked.
- The touched path is verified with the narrowest useful check.
- Logs, errors, and artifacts remain reviewable.

## Do Not Change Casually

- Containment defaults.
- Runtime lifecycle ordering.
- Audit formats and retention behavior.
- Artifact paths and ignore rules.

## graphify

This project has a graphify knowledge graph at graphify-out/.

Rules:
- Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md for god nodes and community structure
- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files
- After modifying code files in this session, run `python3 -c "from graphify.watch import _rebuild_code; from pathlib import Path; _rebuild_code(Path('.'))"` to keep the graph current
