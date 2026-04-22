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

tracked_entries=0
copied_entries=0
missing_entries=0

while IFS= read -r -d '' path; do
  tracked_entries=$((tracked_entries + 1))
  if [ ! -e "$path" ]; then
    missing_entries=$((missing_entries + 1))
    continue
  fi
  mkdir -p "$tmpdir/$(dirname "$path")"
  cp -a "$path" "$tmpdir/$path"
  copied_entries=$((copied_entries + 1))
done < <(git ls-files -z)

echo "tracked_entries=$tracked_entries"
echo "copied_entries=$copied_entries"
echo "missing_entries_skipped=$missing_entries"

gitleaks dir "$tmpdir" --no-banner --redact --config .gitleaks.toml
