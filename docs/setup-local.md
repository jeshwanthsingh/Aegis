# Local Setup

This is the one canonical local setup path for Aegis today.

It is written for a technical Linux user who wants to run the real Firecracker/KVM-backed demo path on one host. It is not written for Mac, Windows, hosted, or multi-tenant deployment.

## Who This Is For

Use this path if all of these are true:

- you are on Linux
- `/dev/kvm` exists and your user can access it
- you can provide a Firecracker binary
- you can provide PostgreSQL server binaries
- you already have the Aegis runtime assets in this repo
- you want the localhost demo runtime, not a production deployment

## What This Path Actually Does

`./scripts/demo_up.sh` is the canonical local bootstrap command. It does all of the following:

- checks `/dev/kvm`
- checks for a Firecracker binary
- checks for PostgreSQL server tools: `initdb`, `pg_ctl`, `psql`
- checks for Go
- checks for:
  - `assets/vmlinux`
  - `assets/alpine-base.ext4`
  - `configs/default-policy.yaml`
  - `db/schema.sql`
- initializes a local Postgres cluster under `/tmp/aegis-demo`
- creates and migrates the local demo database
- runs `go run ./cmd/aegis-cli setup --config .aegis/config.yaml`
- starts the local orchestrator on `127.0.0.1:8080`
- serves the current UI from the same localhost runtime

It does not install system packages for you.

## Prerequisites

You need all of these before the happy path below will work:

- Linux host
- `/dev/kvm` present and accessible to your user
- Firecracker installed, or `AEGIS_FIRECRACKER_BIN` set
- PostgreSQL server binaries installed:
  - `initdb`
  - `pg_ctl`
  - `psql`
- Go toolchain installed
- repo assets already present:
  - `assets/vmlinux`
  - `assets/alpine-base.ext4`

This doc does not claim Mac or Windows support. It does not claim that Aegis self-installs Firecracker, KVM, PostgreSQL, or VM assets.

## Canonical Happy Path

Clone and start the local demo environment:

```bash
git clone https://github.com/jeshwanthsingh/Aegis.git ~/aegis
cd ~/aegis
./scripts/demo_up.sh
```

Check status:

```bash
./scripts/demo_status.sh
```

The runtime should be reachable at:

```text
http://127.0.0.1:8080
```

The UI is served from that same localhost runtime. The CLI demo scripts use the same runtime.

## What Success Looks Like

`./scripts/demo_up.sh` should print output shaped like:

```text
status=started
api_url=http://127.0.0.1:8080
runtime_log=/tmp/aegis-demo/orchestrator.log
postgres_url=postgresql://aegisdemo@127.0.0.1:<port>/aegisdemo?sslmode=disable
proof_root=/tmp/aegis-demo/proofs
next=./scripts/demo_clean.sh
next=./scripts/demo_exfil_denied.sh
next=./scripts/demo_broker_success.sh
next=./scripts/demo_status.sh
next=./scripts/demo_down.sh
```

`./scripts/demo_status.sh` should then print output shaped like:

```text
status=running
api_url=http://127.0.0.1:8080
runtime_pid=<pid>
runtime_log=/tmp/aegis-demo/orchestrator.log
postgres_url=postgresql://aegisdemo@127.0.0.1:<port>/aegisdemo?sslmode=disable
postgres_log=/tmp/aegis-demo/postgres.log
proof_root=/tmp/aegis-demo/proofs
```

## Logs, State, and Proofs

The local demo path keeps its runtime state under `/tmp/aegis-demo`.

Important paths:

- runtime log: `/tmp/aegis-demo/orchestrator.log`
- Postgres log: `/tmp/aegis-demo/postgres.log`
- Postgres data dir: `/tmp/aegis-demo/postgres-data`
- proof bundles: `/tmp/aegis-demo/proofs`
- demo state file: `/tmp/aegis-demo/state.json`

The demo runtime binds to `127.0.0.1:8080` by default. This is intentionally localhost-only.

## Stop The Environment

When you are done:

```bash
./scripts/demo_down.sh
```

Expected output shape:

```text
status=stopped
runtime_log=/tmp/aegis-demo/orchestrator.log
postgres_log=/tmp/aegis-demo/postgres.log
```

## Common Failure Modes

### `/dev/kvm is missing`

The demo harness checks this directly. If you see:

```text
demo error: /dev/kvm is missing; enable KVM before running the demo
```

You are not on the supported happy path yet.

### `/dev/kvm` exists but is not accessible

If you see:

```text
demo error: /dev/kvm is not accessible to the current user: ...
```

Fix your user permissions before retrying.

### Firecracker binary not found

If you see:

```text
demo error: Firecracker binary not found; install firecracker or set AEGIS_FIRECRACKER_BIN
```

Install Firecracker or export `AEGIS_FIRECRACKER_BIN=/path/to/firecracker`.

### PostgreSQL server binaries not found

If you see:

```text
demo error: Postgres tool 'initdb' not found; install PostgreSQL server binaries before running demo_up.sh
```

Install PostgreSQL server binaries, not just a client library.

### Go toolchain not found

If you see:

```text
demo error: Go toolchain not found; install go or add it to PATH before running the demo
```

Install Go before retrying. The demo bootstrap uses `go run ./cmd/aegis-cli setup`.

### Assets missing

If you see a message like:

```text
demo error: kernel image missing at /path/to/repo/assets/vmlinux
```

or

```text
demo error: rootfs image missing at /path/to/repo/assets/alpine-base.ext4
```

The repo is missing the required runtime assets. This setup path assumes those files already exist.

### Another runtime already owns `127.0.0.1:8080`

If you see a message like:

```text
Aegis is already healthy at http://127.0.0.1:8080 but is not owned by the demo state ...
```

Stop the other runtime or reuse it deliberately. `demo_up.sh` refuses to take over an unrelated healthy runtime.

## What This Setup Is Not

This local setup path is:

- Linux-only
- single-host
- localhost-bound by default
- useful for demos and narrow internal validation

It is not:

- a production deployment guide
- a multi-tenant deployment guide
- an enterprise auth guide
- a cross-platform installer
