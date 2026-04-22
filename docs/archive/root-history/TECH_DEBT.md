# Aegis — tracked technical debt

## Orchestrator boot order
`cmd/orchestrator/main.go` connects to Postgres before calling
`policy.Load`. This makes policy-load behavior untestable without a
live database. Fix: load and validate policy first, then connect to
the database. Low-risk refactor, out of scope for Pass A.
