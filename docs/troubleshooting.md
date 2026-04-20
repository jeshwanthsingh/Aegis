# Troubleshooting

This page assumes the canonical local path:

```bash
cd ~/aegis
./scripts/demo_up.sh
./scripts/demo_status.sh
./scripts/demo_clean.sh
```

## `demo_up.sh` fails before the runtime starts

Common messages include:

- `/dev/kvm is missing`
- `/dev/kvm is not accessible to the current user`
- `Firecracker binary not found`
- `Postgres tool 'initdb' not found`
- `Go toolchain not found`
- `kernel image missing`
- `rootfs image missing`

Recovery:

- read the exact `demo error: ...` line first
- compare it against the prerequisite list and failure modes in [setup-local.md](setup-local.md)
- fix the missing dependency or host permission and rerun `./scripts/demo_up.sh`

If `demo_up.sh` says Aegis is already healthy at `http://127.0.0.1:8080` but is not owned by `/tmp/aegis-demo/state.json`, another runtime is already using the canonical demo port. Stop that runtime or reuse it deliberately.

## `demo_status.sh` says `status=degraded`

That means the demo state exists, but the runtime health check is failing.

Inspect the logs:

```bash
tail -n 50 /tmp/aegis-demo/orchestrator.log
tail -n 50 /tmp/aegis-demo/postgres.log
```

Then restart the packaged local environment:

```bash
cd ~/aegis
./scripts/demo_down.sh
./scripts/demo_up.sh
```

`demo_down.sh` leaves logs and proof bundles on disk so you can inspect them after the restart.

## A packaged demo script says the runtime is not healthy

The demo scripts require the localhost runtime from `demo_up.sh`.

Check:

```bash
cd ~/aegis
./scripts/demo_status.sh
```

If it is not running, start it:

```bash
cd ~/aegis
./scripts/demo_up.sh
```

## Repo-local binaries are missing or stale

Symptoms:

- `./.aegis/bin/aegis` is missing
- `./.aegis/bin/orchestrator` is missing
- `./.aegis/bin/aegis-mcp` is missing after setup should have built it

Recovery:

```bash
cd ~/aegis
./scripts/demo_up.sh
```

If you only need to rerun the repo-local setup step without starting the packaged demo runtime:

```bash
cd ~/aegis
go run ./cmd/aegis-cli setup --config .aegis/config.yaml
```

## Receipt verification fails

If `./.aegis/bin/aegis receipt verify --proof-dir ...` fails, the CLI prints `receipt verification failed: ...` and, when available, `verification_failure_class=...`.

Start with:

```bash
cd ~/aegis
./.aegis/bin/aegis receipt show --proof-dir /tmp/aegis-demo/proofs/<execution-id>
./.aegis/bin/aegis receipt verify --proof-dir /tmp/aegis-demo/proofs/<execution-id>
```

Check that the proof directory still contains:

- `receipt.dsse.json`
- `receipt.pub`
- `receipt.summary.txt`
- every bound artifact named in the bundle, such as `stdout.txt`, `stderr.txt`, or `output-manifest.json`

If the bundle was copied elsewhere, keep those files together.

## Runtime unavailable during MCP use

Symptoms:

- the MCP server starts, but `aegis_execute` fails because the runtime cannot be reached

Cause:

- the MCP binary is a thin stdio wrapper around the existing local HTTP runtime
- it does not start the runtime for you

Recovery:

```bash
cd ~/aegis
./scripts/demo_up.sh
AEGIS_BASE_URL=http://127.0.0.1:8080 ./.aegis/bin/aegis-mcp
```
