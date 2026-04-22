#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

declare -a tracked_failures=()

tracked_patterns=(
  '(^|/)\.aegis(/|$)'
  '(^|/)(proofs?|postgres-data|runtime-inputs|tmp)(/|$)'
  '(^|/)(guest-runner/guest-runner|guest-proxy/guest-proxy)$'
  '(^|/)scripts/__pycache__(/|$)'
  '(^|/).*\.pyc$'
  '(^|/).*\.db$'
  '(^|/).*\.sqlite3?$'
  '(^|/)(receipt|approval|lease)_signing_seed'
  '(^|/).*seed\.b64$'
  '(^|/)\.env(\..*)?$'
  '(^|/).*\.pem$'
  '(^|/).*\.key$'
  '^assets/(vmlinux|vmlinux\.old|firecracker)$'
  '^assets/.*\.(ext4|tgz)$'
)

while IFS= read -r path; do
  for pattern in "${tracked_patterns[@]}"; do
    if [[ "$path" =~ $pattern ]]; then
      tracked_failures+=("$path")
      break
    fi
  done
done < <(git ls-files)

if ((${#tracked_failures[@]} > 0)); then
  printf 'tracked hygiene failures:\n' >&2
  printf '  %s\n' "${tracked_failures[@]}" >&2
  exit 1
fi

# The TypeScript SDK ships generated dist/ output intentionally; keep the denylist narrow.
if go list ./... | grep -q '/node_modules/'; then
  printf 'go package discovery hygiene failure:\n' >&2
  printf '  go list ./... traversed a node_modules subtree\n' >&2
  printf '  fix the repo structure or remove the contaminating dependency tree before relying on ./... gates\n' >&2
  exit 1
fi

echo "status=passed"
