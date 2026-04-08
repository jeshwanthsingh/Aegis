#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_URL="${DB_URL:-postgres://postgres:postgres@localhost/aegis?sslmode=disable}"
ASSETS_DIR="${ASSETS_DIR:-$REPO_DIR/assets}"
ROOTFS_PATH="${ROOTFS_PATH:-$REPO_DIR/assets/alpine-base.ext4}"
POLICY_PATH="${POLICY_PATH:-$REPO_DIR/configs/default-policy.yaml}"
ORCH_BIN="${ORCH_BIN:-/tmp/aegis-phase2-orchestrator}"
LOG_FILE="${LOG_FILE:-/tmp/aegis-phase2-validation.log}"
AEGIS_CGROUP_PARENT="${AEGIS_CGROUP_PARENT:-/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/aegis}"
UNIT_NAME="aegis-phase2-validation-$$"

command -v curl >/dev/null 2>&1 || { echo 'missing prerequisite: curl' >&2; exit 1; }
command -v ss >/dev/null 2>&1 || { echo 'missing prerequisite: ss' >&2; exit 1; }
command -v systemd-run >/dev/null 2>&1 || { echo 'missing prerequisite: systemd-run' >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo 'missing prerequisite: systemctl' >&2; exit 1; }

if ss -ltn '( sport = :8080 )' | grep -q ':8080'; then
  echo 'port 8080 is already in use; stop the existing service before running phase2 validation' >&2
  exit 1
fi

cleanup() {
  systemctl --user stop "$UNIT_NAME.scope" >/dev/null 2>&1 || true
  systemctl --user reset-failed "$UNIT_NAME.scope" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"$REPO_DIR/scripts/rebake-guest-runner.sh"
"$REPO_DIR/scripts/preflight.sh"

if command -v go >/dev/null 2>&1; then
  go build -buildvcs=false -o "$ORCH_BIN" "$REPO_DIR/cmd/orchestrator"
elif [ -x "$HOME/local/go/bin/go" ]; then
  "$HOME/local/go/bin/go" build -buildvcs=false -o "$ORCH_BIN" "$REPO_DIR/cmd/orchestrator"
else
  echo 'missing go toolchain' >&2
  exit 1
fi

: >"$LOG_FILE"
launch_cmd="exec \"$ORCH_BIN\" --db \"$DB_URL\" --assets-dir \"$ASSETS_DIR\" --policy \"$POLICY_PATH\" --rootfs-path \"$ROOTFS_PATH\" >>\"$LOG_FILE\" 2>&1"
systemd_cmd=(systemd-run --user --scope --unit "$UNIT_NAME" --property=Delegate=yes --collect --setenv=PATH="$PATH:/sbin:/usr/sbin")
if [ -n "$AEGIS_CGROUP_PARENT" ]; then
  systemd_cmd+=(--setenv=AEGIS_CGROUP_PARENT="$AEGIS_CGROUP_PARENT")
fi
"${systemd_cmd[@]}" /bin/sh -lc "$launch_cmd" >>"$LOG_FILE" 2>&1 &

healthy=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if curl -fsS http://localhost:8080/health >/dev/null; then
    healthy=1
    break
  fi
  sleep 1
done

if [ "$healthy" -ne 1 ]; then
  echo "orchestrator failed health check; recent unit logs:" >&2
  journalctl --user -u "$UNIT_NAME.scope" --no-pager -n 200 >&2 || true
  echo "validation_log=$LOG_FILE" >&2
  exit 1
fi

bash "$REPO_DIR/tests/integration/runtime_events.sh"

echo "validation_log=$LOG_FILE"
echo "grep_runtime_events=grep -n runtime.event.v1 $LOG_FILE"
