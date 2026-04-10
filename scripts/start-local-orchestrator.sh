#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_URL="${DB_URL:-postgres://postgres:postgres@localhost/aegis?sslmode=disable}"
ASSETS_DIR="${ASSETS_DIR:-$REPO_DIR/assets}"
ROOTFS_PATH="${ROOTFS_PATH:-${AEGIS_ROOTFS_PATH:-$REPO_DIR/assets/alpine-base.ext4}}"
POLICY_PATH="${POLICY_PATH:-$REPO_DIR/configs/default-policy.yaml}"
ORCH_BIN="${ORCH_BIN:-/tmp/aegis-bin}"
LOG_FILE="${LOG_FILE:-/tmp/aegis-local-orchestrator.log}"
AEGIS_CGROUP_PARENT="${AEGIS_CGROUP_PARENT:-/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/aegis}"
UNIT_NAME="${UNIT_NAME:-aegis-local-orchestrator}"

command -v systemd-run >/dev/null 2>&1 || { echo 'missing prerequisite: systemd-run' >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo 'missing prerequisite: systemctl' >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo 'missing prerequisite: curl' >&2; exit 1; }

if curl -fsS http://localhost:8080/health >/dev/null 2>&1; then
  echo "reused existing orchestrator"
  exit 0
fi

"$REPO_DIR/scripts/preflight.sh" >/dev/null

if command -v go >/dev/null 2>&1; then
  go build -buildvcs=false -o "$ORCH_BIN" "$REPO_DIR/cmd/orchestrator"
elif [ -x "$HOME/local/go/bin/go" ]; then
  "$HOME/local/go/bin/go" build -buildvcs=false -o "$ORCH_BIN" "$REPO_DIR/cmd/orchestrator"
else
  echo 'missing go toolchain' >&2
  exit 1
fi

systemctl --user stop "$UNIT_NAME.scope" >/dev/null 2>&1 || true
systemctl --user reset-failed "$UNIT_NAME.scope" >/dev/null 2>&1 || true
: >"$LOG_FILE"

setsid systemd-run --user --scope --unit "$UNIT_NAME" --property=Delegate=yes --collect \
  --setenv=PATH="$PATH:/sbin:/usr/sbin" \
  --setenv=AEGIS_CGROUP_PARENT="$AEGIS_CGROUP_PARENT" \
  /bin/sh -lc "exec \"$ORCH_BIN\" --db \"$DB_URL\" --assets-dir \"$ASSETS_DIR\" --policy \"$POLICY_PATH\" --rootfs-path \"$ROOTFS_PATH\" >>\"$LOG_FILE\" 2>&1" \
  >/tmp/${UNIT_NAME}.systemd.log 2>&1 < /dev/null &

for _ in $(seq 1 80); do
  if curl -fsS http://localhost:8080/health >/dev/null 2>&1; then
    echo "orchestrator started"
    echo "log_file=$LOG_FILE"
    exit 0
  fi
  sleep 0.25
done

echo 'orchestrator failed health check' >&2
sed -n '1,160p' /tmp/${UNIT_NAME}.systemd.log >&2 || true
sed -n '1,160p' "$LOG_FILE" >&2 || true
exit 1
