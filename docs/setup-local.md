# Setup Local

This page covers the current local bootstrap path for a real Aegis demo/runtime host.

It is written for one Linux machine with KVM access. It is not a hosted or multi-tenant deployment guide.

## Current Local Bootstrap

1. Check visible prerequisites:

```bash
python3 ./scripts/aegis_demo.py preflight
```

2. Build or refresh repo-local binaries and config when needed:

```bash
go run ./cmd/aegis-cli setup --config .aegis/config.yaml
```

3. Start the local demo runtime:

```bash
./scripts/demo_up.sh
```

4. Confirm runtime health:

```bash
./scripts/demo_status.sh
```

5. Stop it when finished:

```bash
./scripts/demo_down.sh
```

## Visible Prerequisites

Current visible prerequisites include:

- Linux
- `/dev/kvm`
- Firecracker
- PostgreSQL server binaries
- Go
- Python 3
- required kernel/rootfs/assets
- repo-local `.aegis` setup state

This repo is not clone-and-run yet. Preflight exists to make that explicit.

## Local Runtime Paths

The packaged local runtime currently uses:

- state: `/tmp/aegis-demo/state.json`
- logs: `/tmp/aegis-demo/orchestrator.log`, `/tmp/aegis-demo/postgres.log`
- proofs: `/tmp/aegis-demo/proofs`
- repo-local binaries: `./.aegis/bin/*`

## What `demo_up.sh` Is

`./scripts/demo_up.sh` is the current bootstrap wrapper for the local canonical demo/runtime environment. It prepares the visible local state and starts the localhost runtime used by the demo wrappers.

## Next Step

After bootstrap, use [canonical-demos.md](canonical-demos.md) for the current demo flows.

For failure recovery, use [troubleshooting.md](troubleshooting.md).
