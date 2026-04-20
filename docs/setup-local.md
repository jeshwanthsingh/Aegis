# Local Setup

This is the one canonical local setup path for Aegis today.

It is written for a technical Linux user who wants to run the real Firecracker/KVM-backed demo path on one host, inspect the proof bundles it writes, and then tear the runtime down cleanly. It is not written for Mac, Windows, hosted, or multi-tenant deployment.

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
- serves the current operator UI from the same localhost runtime

It does not install system packages for you.

## Tested Baseline

This local path was last checked in the current repo environment with:

- Ubuntu 24.04.4 LTS
- Linux `6.17.0-20-generic`
- `/dev/kvm` present and accessible to the current user
- Go `1.25.9`
- PostgreSQL server binaries `16.13`, resolved from `/usr/lib/postgresql/16/bin`
- Firecracker `v1.7.0` at `/home/cellardoor72/.local/bin/firecracker`

This is a checked baseline, not a broader support matrix. Other distro, kernel, PostgreSQL, Go, and Firecracker versions may work, but they are not documented here as verified.

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

## Runtime Assets

The canonical demo expects these files:

- `assets/vmlinux`
- `assets/alpine-base.ext4`

Current public acquisition paths in this repo are:

- optional release-asset path: `scripts/install.sh` downloads both files from `https://github.com/jeshwanthsingh/Aegis/releases/download/v1.0.0` and verifies them against `scripts/release-checksums.txt`
- optional local rootfs build path: `./scripts/build-alpine-rootfs.sh --output assets/alpine-base.ext4`

Important boundary:

- `scripts/install.sh` is the current public asset-download path, but it is not the canonical bring-up path for the docs
- this repo does not currently document a separate local `vmlinux` build path for the canonical demo
- if you are not using the release asset path for `vmlinux`, the next places to inspect are `scripts/install.sh` and `scripts/release-checksums.txt`

So the current state is:

- rootfs acquisition is documented both as a release download and as a local build path
- kernel acquisition is documented as a release download path, but not yet as a local build path

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

If the demo runtime is already healthy and owned by `/tmp/aegis-demo/state.json`, rerunning `./scripts/demo_up.sh` prints `status=running` and the current connection details instead of starting a second copy.

## Network Modes

Aegis has two canonical network modes:

- `none`: no guest NIC is attached
- `egress_allowlist`: the guest gets a TAP/NAT path, but outbound is still default-deny; only declared FQDNs and CIDRs open TCP `80` / `443`, and the hard deny rules for private ranges, metadata, and guest DNS still apply

An empty `egress_allowlist` is valid and means “networked namespace exists, but nothing external is reachable.”

### Inheritance and timing

- If an execution's intent omits all allowlist fields, it inherits the baseline allowlist in full.
- If an execution's intent provides any allowlist field (`allowed_domains` or `allowed_ips`), the omitted dimension does NOT inherit from baseline; it is treated as empty for that execution. This enforces explicit scope requests.
- FQDN allowlist entries are resolved once at execution start. The resolved IP set is pinned for the lifetime of that execution. Long-running executions where DNS answers rotate may see connection failures after rotation; this is a known, deliberate trade-off eliminating TOCTOU between the DNS interceptor and the firewall.
- Loopback traffic (127.0.0.0/8) is unconditionally permitted inside the guest to support the brokered outbound path. This is reflected explicitly in every receipt's effective allowlist.

## Host privileges for networked demos

The Aegis orchestrator creates TAP devices, manipulates iptables FORWARD chain rules, and configures IP forwarding for guest VMs. These operations require the `CAP_NET_ADMIN`, `CAP_NET_RAW`, and `CAP_NET_BIND_SERVICE` capabilities. Aegis will not run networked executions as an unprivileged user without them.

Two supported options:

1. Grant the capability to the built binaries (recommended for development):

   ```bash
   make setcap
   ```

   This runs `sudo setcap cap_net_admin,cap_net_raw,cap_net_bind_service+eip` on the orchestrator and aegis binaries in `.aegis/bin/`. The grant persists until the binary is rebuilt; rebuilds strip capabilities, so re-run `make setcap` after any `make build` or `go build` that overwrites the binaries. The orchestrator also needs `cap_net_bind_service` to bind the DNS interceptor to UDP port 53 on the TAP gateway address.

2. Run the orchestrator under sudo:

   ```bash
   sudo ./.aegis/bin/orchestrator ...
   ```

   This works but complicates signal handling and is not recommended as the default development workflow.

Aegis deliberately fails loud when the capability is missing rather than falling back to a capability-less mode. A capability-less mode would not enforce iptables rules and would produce receipts claiming enforcement that did not occur. The fail-loud behavior preserves the honesty contract between what receipts claim and what was actually enforced.

### Why ambient capabilities?

Linux file capabilities (set via `setcap`) grant capabilities to a process, but they do NOT propagate to child processes across `execve(2)`. Aegis spawns `ip` and `iptables` as child processes to create TAP devices and manipulate firewall rules. To make those children inherit the needed network capabilities, the orchestrator raises them into the ambient set at startup using `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, ...)`. The ambient set is preserved across `execve`.

If you rebuild the orchestrator, file capabilities are stripped; re-run `make setcap`.

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

The proof root stays empty until you run one of the packaged demo scripts. After any demo run, inspect a bundle with:

```bash
./.aegis/bin/aegis receipt show --proof-dir /tmp/aegis-demo/proofs/<execution-id>
./.aegis/bin/aegis receipt verify --proof-dir /tmp/aegis-demo/proofs/<execution-id>
```

## Stop The Environment

When you are done:

```bash
./scripts/demo_down.sh
```

`demo_down.sh` stops the runtime and Postgres, but it leaves logs and proof bundles under `/tmp/aegis-demo` so you can inspect them afterward.

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

If you do not already have them:

- use `scripts/install.sh` if you want the current public release-asset download path
- use `./scripts/build-alpine-rootfs.sh --output assets/alpine-base.ext4` if you want to build the rootfs locally
- for `vmlinux`, use the release asset path; a separate local kernel build path is not documented here yet

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
