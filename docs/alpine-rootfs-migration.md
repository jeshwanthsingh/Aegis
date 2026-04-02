# Alpine Rootfs Migration

## Goal
Replace the current mislabeled Ubuntu-based guest image with a real Alpine/musl ext4 rootfs without changing the Aegis control-plane architecture, API contract, workspace semantics, or worker-pool semantics.

## Phase 0 findings
Current repo assumptions before migration:
- Firecracker always boots an ext4 rootfs image from `assets/alpine-base.ext4` unless explicitly overridden.
- The guest side expects:
  - `/usr/local/bin/guest-runner`
  - `/usr/bin/python3`
  - `/bin/bash`
  - `ip`/`iproute2`
  - `/dev/vdb` mounted as ext4 at `/workspace`
  - vsock listener on port `1024`
- The existing rootfs build helper at `scripts/build-rootfs.sh` is systemd-oriented and not suitable as the Alpine migration path.
- Current install and CI flows bake `guest-runner` directly into the rootfs image after building it.

## Baseline validation gates
Before switching defaults, run and record all of these against the legacy image:
- `tests/smoke/build_boot.sh`
- `tests/integration/smoke.sh`
- `tests/integration/abuse.sh`
- `tests/integration/allowlist_dns.sh`
- workspace create/write/read/delete flow
- a simple `/v1/execute/stream` request to confirm SSE path parity

## Migration shape
1. Keep the current rootfs available as a rollback artifact.
2. Build a real Alpine ext4 rootfs with `scripts/build-alpine-rootfs.sh`.
3. Select the candidate image via `--rootfs-path` or `AEGIS_ROOTFS_PATH`.
4. Validate parity before making the Alpine image the default production path.

## Rollback path
- Legacy image backup: `assets/ubuntu-legacy.ext4`
- Rootfs override:
  - CLI flag: `--rootfs-path /path/to/image.ext4`
  - env var: `AEGIS_ROOTFS_PATH=/path/to/image.ext4`

## Alpine builder contract
`scripts/build-alpine-rootfs.sh` is responsible for:
- creating a clean ext4 image
- extracting a real Alpine minirootfs
- installing required guest packages (`bash`, `python3`, `iproute2`, `nodejs`, `npm`, `ca-certificates`)
- installing `guest-runner`
- writing a direct `/sbin/init` that launches `guest-runner`
- creating `/workspace` and required runtime directories
- writing an auditable package manifest

## Validation matrix
| Area | Legacy image | Alpine candidate | Notes |
| --- | --- | --- | --- |
| Bash execute | pass (2706ms) | pending | |
| Python execute | pass (11346ms) | pending | |
| Stream/SSE | not tested yet | pending | |
| Workspace read/write | pass (write 3021ms, read 2680ms) | pending | |
| DNS allowlist resolve/deny | pass (confirmed stable) | pending | |
| Worker pool + 429 | pass (5 slots, 429 on overflow) | pending | |
| Teardown cleanup | pass (scratch/socket/cgroup confirmed) | pending | |
| Health/ready/metrics | pass (health/ready/metrics endpoints live) | pending | |

## Benchmark matrix
| Metric | Legacy image | Alpine candidate | Delta | Notes |
| --- | --- | --- | --- | --- |
| Boot to vsock ready | ~2.4s (vsock_connected at 2.4s from start) | pending | pending | Ubuntu glibc/systemd |
| Simple bash execute | 2706ms | pending | pending | wall time incl. boot |
| Simple python execute | 11346ms | pending | pending | python startup slow in Ubuntu |
| Workspace-attached execute | 3021ms write / 2680ms read | pending | pending | |
| Allowlist DNS path | pass | pending | pending | |
| Teardown latency | <300ms | pending | pending | |

## Known migration risks
- interpreter paths are currently distro-specific
- Alpine does not provide systemd, so the old rootfs service model cannot be reused as-is
- Node remains the weakest parity target and should be validated after Python and bash
- no default switch should happen until the Alpine candidate passes the full validation matrix

## Baseline results (Ubuntu legacy image)

Captured 2026-03-30 against  (Ubuntu 24.04 / glibc / systemd 255.4).

- rootfs:  (812MB, Ubuntu, mislabeled)
- init: systemd 255.4-1ubuntu8.14
- libc: glibc ()
- guest-runner startup: via systemd  → 

| Measurement | Value |
| --- | --- |
| Bash execute e2e | 2706ms |
| Python execute e2e | 11346ms |
| Workspace write | 3021ms |
| Workspace read | 2680ms |
| vsock connect | ~2.4s from FC start |
| Health | pass |
| Ready | pass (db_ok=true, 5/5 worker slots) |

Note: python startup is slow (~9s of the 11346ms total) due to glibc + Ubuntu python3 runtime overhead.

## Alpine candidate build status

-  was confirmed to be a Ubuntu image (not Alpine) — not built from Alpine minirootfs.
-  exists from a prior Alpine chroot run but the resulting ext4 was never saved.
- Next step: run  to build a real Alpine image.
