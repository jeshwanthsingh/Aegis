# DECISION_LOG.md
## Alpine/musl over glibc
glibc __check_pf netlink probe races WSL2 network namespace readiness.
Fixed by rebuilding guest on Alpine/musl.

## Single writer goroutine for streaming
Race condition in guest-runner/main.go fixed by single writer pattern.

## External DNS resolver
net.DefaultResolver resolves to loopback unavailable in WSL2.
Forced external resolver via custom dialer.
