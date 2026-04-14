# Troubleshooting

This page covers the common Phase 1 and Phase 2 local validation failures in `~/aegis`.

## `aegis: command not found`

Symptoms:

- `aegis` is not on `PATH`
- `command -v aegis` prints nothing

Recovery:

```bash
cd ~/aegis
bash scripts/install.sh
command -v aegis
```

Expected current path:

```text
~/.local/bin/aegis
```

If you want to inspect the canonical binary directly:

```bash
ls -l ~/aegis/.aegis/bin/aegis ~/.local/bin/aegis
```

## Database unreachable

Symptoms:

- `aegis setup` reports database failure
- `aegis doctor` reports database failure
- `scripts/install.sh` fails while creating the database or applying schema

Checks:

```bash
cd ~/aegis
aegis setup
```

Recovery:

- start PostgreSQL
- ensure the configured URL is correct
- set `AEGIS_DB_URL` or `DB_URL` if your local credentials differ from the default
- rerun:

```bash
cd ~/aegis
aegis setup
```

## Runtime unavailable

Symptoms:

- `aegis doctor` reports runtime unavailable
- SDK or demo scripts fail to reach `http://localhost:8080`

Recovery:

Start the runtime in its own terminal:

```bash
cd ~/aegis
aegis serve
```

Then rerun:

```bash
cd ~/aegis
aegis doctor
```

## Stale `.aegis` state

Symptoms:

- config or binary path looks wrong for the current checkout
- `aegis setup` or `aegis doctor` reports unexpected repo-local binary or config issues
- the shell command resolves to a different binary than the repo-local one

Explicit recovery path:

```bash
cd ~/aegis
rm -rf .aegis
aegis setup
```

Then confirm:

```bash
cd ~/aegis
command -v aegis
aegis setup
```

## Rootfs checksum mismatch or rerun behavior

Symptoms:

- you expected `scripts/install.sh` to revalidate the rootfs against the pristine release checksum on every run
- you are confused because the rootfs digest changed after install

Current behavior:

- `scripts/install.sh` verifies the release checksum when it first downloads `alpine-base.ext4`
- the installer then rebakes `guest-runner` into that repo-local rootfs
- reruns skip the pristine rootfs checksum for an already-present repo-local image because its digest is expected to change after rebake

If you need a clean repo-local runtime rebuild:

```bash
cd ~/aegis
rm -rf .aegis
aegis setup
```

If you need to rebuild the rootfs image itself, rerun:

```bash
cd ~/aegis
bash scripts/install.sh
```

## Missing `python3-venv` or `python3-pip`

This does not block the repo-native exfil demo.

It only blocks Python SDK examples such as `sdk/python/examples/run_code.py`.

Recovery on Debian or Ubuntu:

```bash
sudo apt install python3-venv python3-pip
```

## Missing or stale MCP binary

Symptoms:

- `./.aegis/bin/aegis-mcp` is missing
- MCP client registration points at a stale or missing binary

Recovery:

```bash
cd ~/aegis
aegis setup
ls -l .aegis/bin/aegis-mcp
```

If you need to force a rebuild immediately after MCP source changes:

```bash
cd ~/aegis
go build -buildvcs=false -o .aegis/bin/aegis-mcp ./cmd/aegis-mcp
```

## Runtime unavailable during MCP use

Symptoms:

- the MCP server starts, but `aegis_execute` fails because the runtime cannot be reached

Cause:

- the MCP binary is only a thin stdio wrapper around the existing local HTTP runtime
- it does not embed or start the runtime for you

Recovery:

```bash
cd ~/aegis
aegis serve
```

In another terminal:

```bash
cd ~/aegis
AEGIS_BASE_URL=http://localhost:8080 ./.aegis/bin/aegis-mcp
```
