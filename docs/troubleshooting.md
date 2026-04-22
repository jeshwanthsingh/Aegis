# Troubleshooting

This page assumes the canonical local operator path:

```bash
python3 ./scripts/aegis_demo.py preflight
./scripts/demo_up.sh
./scripts/demo_status.sh
```

## Preflight Fails

Run:

```bash
python3 ./scripts/aegis_demo.py preflight
```

Then split the failure into one of these two buckets.

### Repo-local state is missing

If preflight reports missing repo-local binaries, config, or signing seed, run:

```bash
go run ./cmd/aegis-cli setup --config .aegis/config.yaml
python3 ./scripts/aegis_demo.py preflight
```

### Host prerequisites are missing

Fix the exact missing host dependency first:

- `/dev/kvm` missing or inaccessible
- Firecracker missing
- Postgres server binaries missing
- kernel or rootfs asset missing
- Go missing

`setup` does not install those host prerequisites for you.

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

## Approval-Requiring Demos Fail

Current runtime approval verification requires explicit public-key verifier config.

If an approval-requiring demo fails:

1. confirm `AEGIS_APPROVAL_PUBLIC_KEYS_JSON` is set for the runtime
2. if you are issuing approvals locally with `AEGIS_APPROVAL_SIGNING_SEED_B64`, derive the matching public-key map with:

```bash
./.aegis/bin/aegis approval public-keys
```

3. ensure the runtime is using that exact public-key map

If verifier config is missing, approval checks fail closed.

## Lease-Related Admission Failures

Executions that need leases fail before VM start if lease issuance cannot succeed.

Look for:

- `lease_issue_failed`

This is an admission or infrastructure failure, not a fake runtime receipt event.

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
- the bound artifacts referenced by the receipt

If the bundle was copied, keep those files together.

## `host_repo_apply_patch` Demo Issues

If the approved host patch demo fails:

- confirm the base revision still matches
- confirm the target repo is `/tmp/aegis-demo/host-repos/demo-repo`
- confirm another local process is not contending on the advisory lock
- confirm the target repo is dedicated or quiesced during the demo

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

to get the exact missing prerequisite, then fix that host-level dependency.

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

## Native Linux vs WSL2

WSL2 is useful for development, but native Linux is the recommended demo and validation baseline. If you hit timing, KVM, networking, or mount oddities on WSL2, retry on native Linux before assuming a runtime bug.
