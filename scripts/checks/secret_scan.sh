#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

export PATH="$HOME/go/bin:$PATH"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "missing required tool: gitleaks" >&2
  echo "install it explicitly with:" >&2
  echo "  go install github.com/zricethezav/gitleaks/v8@v8.24.2" >&2
  exit 1
fi

echo "scope=working_tree_only"
echo "tracked_scope=tracked_and_indexed_working_tree_only"
echo "history_scan=not_included"
echo "reason=Phase 13 keeps the secret gate deterministic and repo-local; it scans the current tracked working tree rather than local ignored runtime state"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

git ls-files -z | tar --null -T - -cf - | tar -xf - -C "$tmpdir"

gitleaks dir "$tmpdir" --no-banner --redact --config .gitleaks.toml
