# Setup Local

This is the one canonical setup/install doc for external testers.

The path here is intentionally narrow:

- one Linux host
- Firecracker/KVM
- local Postgres
- repo-local `.aegis/` bootstrap state

This is not a hosted deployment guide, and it is not clone-and-run yet.

## 1. Ubuntu amd64 local-demo prerequisites

This section is for:

- Ubuntu amd64
- one local machine
- the local demo path in this repo
- a brand new machine with nothing installed yet

### A. Enable hardware virtualization in BIOS or UEFI

Aegis needs `/dev/kvm`. If hardware virtualization is disabled in BIOS or UEFI, `/dev/kvm` will not exist and preflight will fail.

There is no shell command for this step. Enable Intel VT-x or AMD-V in firmware first, then boot Ubuntu.

### B. Install the host packages

```bash
sudo apt-get update
sudo apt-get install -y git python3 curl ca-certificates postgresql postgresql-client iproute2 iptables e2fsprogs
```

### C. Install the pinned Go toolchain from `go.mod`

Do not rely on Ubuntu's default `golang-go` package here. This repo currently pins Go `1.25.9`.

```bash
cd /tmp
curl -LO https://go.dev/dl/go1.25.9.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.25.9.linux-amd64.tar.gz
printf 'export PATH=/usr/local/go/bin:$PATH\n' | sudo tee /etc/profile.d/go.sh >/dev/null
export PATH=/usr/local/go/bin:$PATH
go version
```

### D. Start PostgreSQL and make the default local demo database URL work

This is local demo guidance only. It is not production guidance.

The default local config uses `postgres://postgres:postgres@localhost/aegis?sslmode=disable`.

```bash
sudo systemctl enable --now postgresql
sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'postgres';"
```

`aegis setup` creates the `aegis` database later if it does not already exist.

### E. Make KVM accessible to your user

```bash
sudo groupadd -f kvm
sudo usermod -aG kvm "$USER"
newgrp kvm
```

If the new group membership does not apply cleanly, log out and log back in instead of using `newgrp`.

If `/dev/kvm` is still missing after that, load the KVM modules for the current CPU:

```bash
sudo modprobe kvm
sudo modprobe kvm_intel
```

On AMD hosts, use:

```bash
sudo modprobe kvm
sudo modprobe kvm_amd
```

### F. Clone the repo

```bash
git clone https://github.com/jeshwanthsingh/Aegis.git aegis
cd aegis
```

### G. Install the pinned Firecracker binary from the release asset

```bash
curl -L https://github.com/jeshwanthsingh/Aegis/releases/download/v1.0.0/firecracker -o /tmp/firecracker
echo '835bb33a7f4b75e924bc0635385951a55fbd4293964a956a6b4ad35345ce5419  /tmp/firecracker' | sha256sum -c -
sudo install -m 0755 /tmp/firecracker /usr/local/bin/firecracker
```

### H. Download the pinned guest assets

```bash
mkdir -p assets
curl -L https://github.com/jeshwanthsingh/Aegis/releases/download/v1.0.0/vmlinux -o assets/vmlinux
echo 'ea5e7d5cf494a8c4ba043259812fc018b44880d70bcbbfc4d57d2760631b1cd6  assets/vmlinux' | sha256sum -c -
curl -L https://github.com/jeshwanthsingh/Aegis/releases/download/v1.0.0/alpine-base.ext4 -o assets/alpine-base.ext4
echo '6493987a9930fccae923ef2cd1ea7aa4d1c55ff6548a2fa3a59fc6e27697be3f  assets/alpine-base.ext4' | sha256sum -c -
```

### I. Machine-ready verification

Run this block from the repo root:

```bash
ls -l /dev/kvm
firecracker --version
psql --version
go version
python3 ./scripts/aegis_demo.py preflight
```

At this point, the host prerequisites should be in place. The first `preflight` run may still report missing repo-local Aegis state under `./.aegis/`. That is expected before the next section.

## 2. After machine prerequisites are installed, start the Aegis repo flow

Run these commands from the repo root:

```bash
python3 ./scripts/aegis_demo.py preflight
go run ./cmd/aegis-cli setup --config .aegis/config.yaml
python3 ./scripts/aegis_demo.py preflight
```

`preflight` is the current source of truth for the machine and the checkout. It checks:

- Linux
- `/dev/kvm`
- repo-local `./.aegis/bin/aegis`
- repo-local `./.aegis/bin/orchestrator`
- `.aegis/config.yaml`
- `assets/vmlinux`
- `assets/alpine-base.ext4`
- `.aegis/receipt_signing_seed.b64`
- Firecracker
- Go
- PostgreSQL server binaries: `initdb`, `pg_ctl`, `psql`

What `aegis setup` bootstraps:

- creates `.aegis/` and config if missing
- builds repo-local `aegis`, `aegis-mcp`, and `orchestrator`
- builds `guest-runner`
- generates the receipt signing seed if missing
- bootstraps the configured database schema
- rebakes `guest-runner` into the rootfs if the rootfs already exists

What `aegis setup` does not do:

- enable KVM
- install Firecracker
- install PostgreSQL server binaries
- fetch missing guest assets for you

The second `preflight` run should print `status=ok`. If it still fails, fix the exact issue it prints before continuing.

Native Linux is the recommended demo host. WSL2 is useful for development, but it is not the cleanest validation baseline.

## 3. Start the local runtime

```bash
./scripts/demo_up.sh
./scripts/demo_status.sh
```

Expected state is `status=started` or `status=running`.

The demo runtime writes state under `/tmp/aegis-demo`:

- runtime state: `/tmp/aegis-demo/state.json`
- runtime log: `/tmp/aegis-demo/orchestrator.log`
- Postgres log: `/tmp/aegis-demo/postgres.log`
- proofs: `/tmp/aegis-demo/proofs`
- demo artifacts: `/tmp/aegis-demo/artifacts`
- demo host repo: `/tmp/aegis-demo/host-repos/demo-repo`

## 4. Run the first successful demo path

The recommended first demo is the governed HTTP success path:

```bash
python3 ./scripts/aegis_demo.py broker-http
```

Why this is the best first run:

- it exercises the current brokered HTTP path
- it auto-previews the exact governed request with `aegis demo prepare`
- it auto-issues a local approval ticket for that exact request
- it ends with a receipt you can verify offline

For the full A-D demo set, use [canonical-demos.md](canonical-demos.md).

## 5. Verify the receipt

Each demo prints:

- `execution_id`
- `proof_dir`
- `verify_command`

Rerun the exact `verify_command` line from demo output.

Generic form:

```bash
./.aegis/bin/aegis receipt verify --proof-dir /tmp/aegis-demo/proofs/<execution_id>
./.aegis/bin/aegis receipt show --proof-dir /tmp/aegis-demo/proofs/<execution_id>
```

## 6. Stop the runtime

```bash
./scripts/demo_down.sh
```

## Practical Notes

- Python and bash are the strongest demo paths today. Node is supported, but less battle-tested.
- Compute profiles are real, but today they change VM shape first; they are not a broader resource-envelope claim.
- The approved host-patch demo modifies only `/tmp/aegis-demo/host-repos/demo-repo`, not the Aegis checkout itself.

If any step above fails, use [troubleshooting.md](troubleshooting.md).
