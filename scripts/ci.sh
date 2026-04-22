#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/go/bin:$PATH"

STATICCHECK_VERSION="2025.1.1"
GOVULNCHECK_VERSION="v1.1.4"
GITLEAKS_VERSION="v8.24.2"

INSTALL_TOOLS=0

usage() {
  cat <<'EOF'
usage: ./scripts/ci.sh [--install-tools]

Repo-local quality and security gates for Aegis.

This script proves:
- deterministic repo-local tests
- go vet
- staticcheck
- govulncheck
- repo hygiene
- working-tree secret scan

It does NOT prove live Firecracker/KVM/Postgres canonical demos.

Options:
  --install-tools   explicitly install pinned staticcheck, govulncheck, and gitleaks before running gates
EOF
}

while (($# > 0)); do
  case "$1" in
    --install-tools)
      INSTALL_TOOLS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

step() {
  printf '\n==> %s\n' "$1"
}

require_tool() {
  local name="$1"
  local install_cmd="$2"
  if command -v "$name" >/dev/null 2>&1; then
    return 0
  fi
  echo "missing required tool: $name" >&2
  echo "install it explicitly with:" >&2
  echo "  $install_cmd" >&2
  exit 1
}

if ((INSTALL_TOOLS)); then
  step "Installing pinned Go analysis tools"
  (
    cd "$ROOT_DIR"
    go install "honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}"
    go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"
    go install "github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION}"
  )
fi

require_tool staticcheck "go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}"
require_tool govulncheck "go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"
require_tool gitleaks "go install github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION}"
require_tool python3 "use your package manager to install python3"
require_tool go "install Go ${GOVERSION:-1.25.9}"

step "CI scope"
echo "scope=repo_local_quality_gates"
echo "kvm_demo_coverage=not_included"
echo "reason=GitHub-hosted and repo-local runs do not prove live Firecracker/KVM/Postgres canonical demos"

step "Repo hygiene"
"$ROOT_DIR/scripts/checks/repo_hygiene.sh"

step "Root module tests"
(
  cd "$ROOT_DIR"
  go test -count=1 ./...
)

step "Guest runner tests"
(
  cd "$ROOT_DIR/guest-runner"
  go test -count=1 ./...
)

step "Guest proxy tests"
(
  cd "$ROOT_DIR/guest-proxy"
  go test -count=1 ./...
)

step "Python demo-helper tests"
(
  cd "$ROOT_DIR"
  python3 -m unittest scripts/test_aegis_demo.py
)

step "Root module go vet"
(
  cd "$ROOT_DIR"
  go vet ./...
)

step "Guest runner go vet"
(
  cd "$ROOT_DIR/guest-runner"
  go vet ./...
)

step "Guest proxy go vet"
(
  cd "$ROOT_DIR/guest-proxy"
  go vet ./...
)

step "Root module staticcheck"
(
  cd "$ROOT_DIR"
  staticcheck ./...
)

step "Guest runner staticcheck"
(
  cd "$ROOT_DIR/guest-runner"
  staticcheck ./...
)

step "Guest proxy staticcheck"
(
  cd "$ROOT_DIR/guest-proxy"
  staticcheck ./...
)

step "Root module govulncheck"
(
  cd "$ROOT_DIR"
  govulncheck ./...
)

step "Guest runner govulncheck"
(
  cd "$ROOT_DIR/guest-runner"
  govulncheck ./...
)

step "Guest proxy govulncheck"
(
  cd "$ROOT_DIR/guest-proxy"
  govulncheck ./...
)

step "Working-tree secret scan"
"$ROOT_DIR/scripts/checks/secret_scan.sh"

step "Race-test decision"
echo "race_tests=deferred"
echo "reason=Phase 13 keeps deterministic repo-local gates only; no stable bounded race-test package set has been carved out yet across the mixed KVM/process/filesystem code paths"

step "Result"
echo "status=passed"
