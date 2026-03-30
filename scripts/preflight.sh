#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_URL_DEFAULT="postgres://postgres:postgres@localhost/postgres?sslmode=disable"
DB_URL="${DB_URL:-$DB_URL_DEFAULT}"
FAILURES=0

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
  if [ -f "$REPO_DIR/assets/alpine-base.ext4" ]; then
    pass "rootfs"
  else
    fail "rootfs" "missing $REPO_DIR/assets/alpine-base.ext4"
  fi
}

check_cgroup_v2() {
  if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null || true)" = "cgroup2fs" ]; then
    pass "cgroup v2"
  else
    fail "cgroup v2" "/sys/fs/cgroup is not mounted as cgroup2fs"
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
  if PGPASSWORD="${PGPASSWORD:-}" psql -w "$DB_URL" -c 'select 1' >/dev/null 2>&1; then
    pass "postgres"
  else
    fail "postgres" "unable to connect using DB_URL=${DB_URL} without prompting; set DB_URL or PGPASSWORD appropriately"
  fi
}

check_linux
check_kvm
check_firecracker
check_kernel_image
check_rootfs
check_cgroup_v2
check_iptables
check_postgres

if [ "$FAILURES" -ne 0 ]; then
  printf 'preflight failed with %d issue(s)\n' "$FAILURES" >&2
  exit 1
fi

printf 'preflight passed\n'
