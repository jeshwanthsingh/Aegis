## Handoff: 2026-04-10 MCP Python runtime hang follow-up
## Status: BLOCKED
## What shipped:
- added timeout diagnostics in `guest-runner/main.go` so timed-out Python runs expose `/proc` state, `wchan`, and `syscall`
- proved the remaining blocker is deeper than MCP request shaping: current WSL-local MCP Python can still time out before user code, even with no workspace writes
- reverted two unsuccessful debugging experiments: post-open tracer fd inspection and temporary Python `-I -B` startup flags
## Decisions forced (write to DECISION_LOG.md if significant):
- none
## Remaining in phase:
- isolate why guest Python startup still stalls under the current guest-runner branch before it reaches the user script
- then rerun the required MCP matrix for clean print, `/tmp` write/read, forbidden `/etc` write, and malicious `os.system("curl ...")`
## Blockers:
- WSL-local MCP Python execution still times out under `divergence_verdict=allow`; observed timeout states now vary between disk-wait, ptrace-stop, and running, so the root cause is still unresolved in guest runtime startup
## Next prompt for Claude:
The MCP layer is no longer the lead suspect. I added timeout diagnostics and proved current guest Python still times out before user code even on a no-workspace MCP run. Next investigate the guest Python startup/runtime path itself on the current branch, using the execution ids and `wchan/syscall` evidence in `ai/EXECUTION_LOG.md` rather than reopening MCP, broker, or warm-pool work.
