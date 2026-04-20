# Aegis — tracked technical debt

## Orchestrator boot order
`cmd/orchestrator/main.go` connects to Postgres before calling
`policy.Load`. This makes policy-load behavior untestable without a
live database. Fix: load and validate policy first, then connect to
the database. Low-risk refactor, out of scope for Pass A.

## Shell-out to ip/iptables from executor
`internal/executor/lifecycle.go` spawns `ip` and `iptables`
as child processes. This requires the ambient-capabilities
workaround and introduces a process-spawn overhead per rule.
Replace with direct netlink syscalls (github.com/vishvananda/netlink)
and nftables Go bindings in a future pass. Non-blocking for
current use.

## DNS interceptor uses privileged port 53 directly
The orchestrator binds UDP/53 in-process, requiring
`cap_net_bind_service`. A cleaner architecture is to bind the
interceptor to a high port (e.g., 5353) and DNAT-redirect
guest DNS queries to it via iptables. This would eliminate
the cap_net_bind_service requirement and reduce the
orchestrator's capability surface to just cap_net_admin +
cap_net_raw. Non-blocking for current use. Defer to a future
pass.
