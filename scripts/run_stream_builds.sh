#!/usr/bin/env bash
set -euo pipefail
cd /home/cellardoor/aegis
printf "=== BUILD ALL ===\n"
/home/cellardoor/local/go/bin/go build -buildvcs=false ./...
printf "\n=== BUILD ORCHESTRATOR ===\n"
/home/cellardoor/local/go/bin/go build -buildvcs=false -o /tmp/aegis-bin ./cmd/orchestrator
printf "\n=== BUILD CLI ===\n"
/home/cellardoor/local/go/bin/go build -buildvcs=false -o /tmp/aegis-cli ./cmd/aegis-cli
printf "\n=== BUILD GUEST ===\n"
cd /home/cellardoor/aegis/guest-runner
/home/cellardoor/local/go/bin/go build -a -o guest-runner .