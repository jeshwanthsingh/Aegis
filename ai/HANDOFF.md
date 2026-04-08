## Handoff: 2026-04-08 Phase 2 - AF_INET connect closure
## Status: COMPLETE
## What shipped:
- Canonical `guest-runner` rebake path with baked freshness metadata in `/etc/aegis-guest-runner.json`
- Configurable delegated cgroup parent path for local Firecracker validation
- Real guest-side ptrace lifecycle/connect sensor for `process.exec`, `process.fork`, `process.exit`, and `net.connect`
- Canonical Phase 2 Firecracker validation script now passes on a real run
- `/proc` remains temporary `file.open` fallback only
## Decisions forced (write to DECISION_LOG.md if significant):
- The canonical Phase 2 connect proof now uses a direct bash `/dev/tcp` AF_INET attempt because it is simpler and more deterministic than the earlier Python probe in this environment
## Remaining in phase:
- none
## Blockers:
- none
## Next prompt for Claude:
Phase 2 is complete. Real Firecracker validation now proves normalized `runtime.event.v1` for `process.exec`, `process.fork`, `process.exit`, and `net.connect`, with `/proc` left only as temporary `file.open` fallback. Claude can write the Phase 3 brief next, but should keep the deferred Phase 2 leftovers explicitly out of scope unless they are required by Phase 3.