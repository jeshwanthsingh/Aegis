# Troubleshooting

This page assumes the current local operator path:

```bash
python3 ./scripts/aegis_demo.py preflight
./scripts/demo_up.sh
./scripts/demo_status.sh
```

## Demo Preflight Fails

Run:

```bash
python3 ./scripts/aegis_demo.py preflight
```

The preflight reports visible missing prerequisites such as:

- Linux requirement
- missing or inaccessible `/dev/kvm`
- Firecracker missing
- missing Postgres server binaries
- missing repo-local config
- missing kernel/rootfs/assets
- missing repo-local binaries

Fix the reported prerequisite first. The canonical demos are intentionally not clone-and-run yet.

## `demo_up.sh` Fails Before The Runtime Starts

Common causes:

- `/dev/kvm` is missing or inaccessible
- Firecracker is not installed
- Postgres tools like `initdb` or `pg_ctl` are missing
- required guest assets are missing
- `.aegis` local setup state is incomplete

Inspect the exact `demo error: ...` output and the preflight output together before retrying.

## `demo_status.sh` Reports Degraded Or Unhealthy

Inspect:

```bash
tail -n 50 /tmp/aegis-demo/orchestrator.log
tail -n 50 /tmp/aegis-demo/postgres.log
```

If the runtime is wedged, restart it:

```bash
./scripts/demo_down.sh
./scripts/demo_up.sh
```

## Approval-Requiring Demos Fail With Approval Verification Errors

Current runtime approval verification requires explicit public-key verifier config.

If the runtime cannot verify issued approvals:

1. confirm `AEGIS_APPROVAL_PUBLIC_KEYS_JSON` is set for the runtime
2. if you are issuing approvals locally with `AEGIS_APPROVAL_SIGNING_SEED_B64`, derive the matching public-key map with:

```bash
./.aegis/bin/aegis approval public-keys
```

3. ensure the runtime is using that exact public-key map

If the runtime verifier config is missing, approval checks fail closed as unavailable.

## Lease-Related Admission Failures

Executions that need leases now fail before VM start if lease issuance cannot succeed.

Look for:

- `lease_issue_failed`

This is an admission/infrastructure failure, not a fake runtime receipt event.

## Receipt Verification Fails

Start with:

```bash
./.aegis/bin/aegis receipt show --proof-dir /tmp/aegis-demo/proofs/<execution_id>
./.aegis/bin/aegis receipt verify --proof-dir /tmp/aegis-demo/proofs/<execution_id>
```

Check that the proof directory still contains:

- `receipt.dsse.json`
- `receipt.pub`
- `receipt.summary.txt`
- bound artifacts referenced by the receipt

If the bundle was copied, keep those files together.

## `host_repo_apply_patch` Demo Issues

If the approved host patch demo fails:

- confirm the repo label is configured as expected
- confirm the base revision still matches
- confirm the target repo is dedicated or quiesced during the demo
- confirm another local process is not contending on the advisory lock

The current host patch path uses a local-host advisory lock, not a distributed or mandatory lock.

## Firecracker Or KVM-Specific Problems

Typical failures:

- missing `/dev/kvm`
- permission denied on `/dev/kvm`
- Firecracker binary missing
- kernel/rootfs asset mismatch

Use:

```bash
python3 ./scripts/aegis_demo.py preflight
```

to get the exact visible prerequisite failure, then fix that host-level dependency.

## Postgres Problems

Typical failures:

- `initdb` missing
- `pg_ctl` missing
- stale local Postgres state under `/tmp/aegis-demo`

Inspect:

```bash
tail -n 50 /tmp/aegis-demo/postgres.log
```

Then restart the local demo runtime if needed:

```bash
./scripts/demo_down.sh
./scripts/demo_up.sh
```

## Repo-Local Binaries Are Missing Or Stale

If `./.aegis/bin/aegis` or `./.aegis/bin/orchestrator` is missing or stale:

```bash
go run ./cmd/aegis-cli setup --config .aegis/config.yaml
```

Then rerun preflight.

## MCP Runtime Unavailable

`aegis-mcp` talks to the existing local HTTP runtime. It does not bootstrap the runtime on its own.

Start the runtime first:

```bash
./scripts/demo_up.sh
AEGIS_BASE_URL=http://127.0.0.1:8080 ./.aegis/bin/aegis-mcp
```
