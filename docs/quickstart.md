# Quickstart

This file is no longer the canonical first-run guide.

The old `install.sh` / `aegis setup` / `aegis serve` / receiver-based exfil flow in this file was the source of setup drift. The current repo-local happy path is the packaged localhost demo flow.

Use these docs instead:

- [setup-local.md](setup-local.md): the one canonical Linux/KVM local setup path
- [demo-guide.md](demo-guide.md): the three packaged demos and what they prove

If you want the shortest possible current path, use:

```bash
git clone https://github.com/jeshwanthsingh/Aegis.git ~/aegis
cd ~/aegis
./scripts/demo_up.sh
./scripts/demo_clean.sh
./scripts/demo_exfil_denied.sh
./scripts/demo_broker_success.sh
./scripts/demo_down.sh
```
