# REPO_MAP.md

## Entrypoints
| Command | What it does |
|---------|-------------|
| `sudo env "PATH=$PATH" /tmp/aegis-bin --db '...'` | Start orchestrator (needs sudo for KVM+cgroup) |
| `bash scripts/run-demo.sh` | Run 4 threat-model tests |
| `bash scripts/install.sh` | Install on fresh machine (run as root) |
| `bash scripts/build-rootfs.sh` | Apply rootfs modifications |
| `bash scripts/benchmark.sh` | 10 sequential runs, min/max/avg |

## Hot paths
- **VM boot:** `internal/executor/firecracker.go` → `NewVM()`
- **Execution transport:** `internal/executor/vsock.go` → `SendPayload()`
- **Resource limits:** `internal/executor/lifecycle.go` → `SetupCgroup()` / `Teardown()`
- **HTTP API:** `internal/api/handler.go` → `NewHandler()`, `WithAuth()`, `HandleHealth()`
- **Guest side:** `guest-runner/main.go` → `main()`, `resolveInterpreter()`

## Important paths
```
~/aegis/
├── cmd/orchestrator/main.go       ← binary entrypoint, reads AEGIS_API_KEY
├── internal/
│   ├── api/handler.go             ← HTTP handlers + auth + health
│   ├── executor/
│   │   ├── firecracker.go         ← VM lifecycle, PUT sequence incl. /entropy
│   │   ├── vsock.go               ← UDS proxy protocol, deadline-aware SendPayload
│   │   ├── lifecycle.go           ← cgroup v2 setup/teardown
│   │   └── pool.go                ← 5-slot counting semaphore
│   ├── store/postgres.go          ← audit log
│   └── models/types.go            ← Payload, Result
├── guest-runner/main.go           ← static binary inside VM (separate module)
├── scripts/
│   ├── run-demo.sh                ← 4 tests
│   ├── install.sh                 ← fresh-machine installer
│   ├── build-rootfs.sh            ← rootfs modification script
│   └── benchmark.sh               ← timing benchmarks
├── assets/                        ← vmlinux + alpine-base.ext4 (gitignored)
├── db/schema.sql                  ← executions table
└── HANDOFF.md                     ← current session state
```

## Assets (gitignored — large files)
- `assets/vmlinux` — Firecracker kernel, ~21MB, from AWS S3
- `assets/alpine-base.ext4` — Ubuntu 22.04 rootfs ~800MB (resized), Node.js v20 installed
