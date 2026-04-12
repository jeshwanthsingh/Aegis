#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${AEGIS_CONFIG:-$REPO_DIR/.aegis/config.yaml}"
ROOTFS_IMAGE="${ROOTFS_PATH:-${AEGIS_ROOTFS_PATH:-$REPO_DIR/assets/alpine-base.ext4}}"
DEFAULT_CGROUP_PARENT="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/aegis"
CGROUP_PARENT="${AEGIS_CGROUP_PARENT:-$DEFAULT_CGROUP_PARENT}"
FAILURES=0

config_db_url() {
  if [ ! -f "$CONFIG_PATH" ]; then
    return 0
  fi
  awk '
    $1 == "database:" { in_db = 1; next }
    in_db && $1 == "url:" {
      sub(/^[[:space:]]*url:[[:space:]]*/, "", $0)
      gsub(/^"/, "", $0)
      gsub(/"$/, "", $0)
      print
      exit
    }
    in_db && /^[^[:space:]]/ { in_db = 0 }
  ' "$CONFIG_PATH"
}

DB_URL="${DB_URL:-${AEGIS_DB_URL:-$(config_db_url)}}"

pass() {
  printf 'PASS %s\n' "$1"
}

fail() {
  printf 'FAIL %s: %s\n' "$1" "$2" >&2
  FAILURES=$((FAILURES + 1))
}

check_linux() {
  if [ "$(uname -s)" = "Linux" ]; then
    pass "linux"
  else
    fail "linux" "Aegis requires Linux"
  fi
}

check_kvm() {
  if [ ! -e /dev/kvm ]; then
    fail "kvm" "/dev/kvm is missing"
    return
  fi
  if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    pass "kvm"
    return
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n test -r /dev/kvm && sudo -n test -w /dev/kvm; then
    pass "kvm (via sudo)"
    return
  fi
  fail "kvm" "/dev/kvm exists but is not directly accessible by $(id -un); add the user to the kvm group or run Aegis via sudo"
}

check_firecracker() {
  if command -v firecracker >/dev/null 2>&1; then
    pass "firecracker"
  else
    fail "firecracker" "firecracker binary not found on PATH"
  fi
}

check_kernel_image() {
  if [ -f "$REPO_DIR/assets/vmlinux" ]; then
    pass "kernel image"
  else
    fail "kernel image" "missing $REPO_DIR/assets/vmlinux"
  fi
}

check_rootfs() {
  if [ -f "$ROOTFS_IMAGE" ]; then
    pass "rootfs"
  else
    fail "rootfs" "missing $ROOTFS_IMAGE"
  fi
}

check_cgroup_v2() {
  if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null || true)" = "cgroup2fs" ]; then
    pass "cgroup v2"
  else
    fail "cgroup v2" "/sys/fs/cgroup is not mounted as cgroup2fs"
  fi
}

check_cgroup_parent() {
  local parent="$CGROUP_PARENT"
  local parent_dir
  parent_dir="$(dirname "$parent")"
  if [ ! -d "$parent_dir" ]; then
    fail "cgroup parent" "parent directory missing: $parent_dir"
    return
  fi
  if [ ! -w "$parent_dir" ]; then
    fail "cgroup parent" "parent directory not writable: $parent_dir (set AEGIS_CGROUP_PARENT to a writable delegated subtree or run with sufficient privileges)"
    return
  fi
  mkdir -p "$parent" 2>/dev/null || { fail "cgroup parent" "unable to create $parent"; return; }
  if printf '+cpu +memory +pids' >"$parent/cgroup.subtree_control" 2>/dev/null; then
    pass "cgroup parent"
  else
    fail "cgroup parent" "unable to enable controllers in $parent/cgroup.subtree_control"
  fi
}

check_iptables() {
  if command -v iptables >/dev/null 2>&1; then
    pass "iptables"
  else
    fail "iptables" "iptables not found on PATH"
  fi
}

check_postgres() {
  if ! command -v psql >/dev/null 2>&1; then
    fail "postgres" "psql not found on PATH"
    return
  fi
  if [ -z "$DB_URL" ]; then
    fail "postgres" "database URL unresolved; run 'go run ./cmd/aegis-cli setup' or set DB_URL/AEGIS_DB_URL"
    return
  fi
  if PGPASSWORD="${PGPASSWORD:-}" psql -w "$DB_URL" -c 'select 1' >/dev/null 2>&1; then
    pass "postgres"
  else
    fail "postgres" "unable to connect using DB_URL=${DB_URL} without prompting; update .aegis/config.yaml or set DB_URL/AEGIS_DB_URL and PGPASSWORD appropriately"
  fi
}

check_linux
check_kvm
check_firecracker
check_kernel_image
check_rootfs
check_cgroup_v2
check_cgroup_parent
check_iptables
check_postgres

if [ "$FAILURES" -ne 0 ]; then
  printf 'preflight failed with %d issue(s)\n' "$FAILURES" >&2
  exit 1
fi

printf 'preflight passed\n'
