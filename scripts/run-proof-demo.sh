#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
GO_BIN="${GO_BIN:-/home/cellardoor/local/go/bin/go}"
START_SCRIPT="${START_SCRIPT:-$HOME/aegis/scripts/start-local-orchestrator.sh}"
CLI_CMD=("$GO_BIN" run ./cmd/aegis-cli)
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if ! curl -fsS "$BASE_URL/health" >/dev/null 2>&1; then
  echo "orchestrator not healthy; start it with: $START_SCRIPT" >&2
  exit 1
fi

new_exec_id() {
  python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
}

run_case() {
  local label="$1"
  local lang="$2"
  local code_file="$3"
  local intent_file="$4"
  local expected_verdict="$5"
  local expected_artifacts="$6"

  local payload_file="$TMPDIR/${label}.payload.json"
  python3 - <<PY "$lang" "$code_file" "$intent_file" "$payload_file"
import json, pathlib, sys
lang, code_path, intent_path, payload_path = sys.argv[1:]
payload = {
    "lang": lang,
    "code": pathlib.Path(code_path).read_text(),
    "timeout_ms": 8000,
    "intent": json.loads(pathlib.Path(intent_path).read_text()),
}
pathlib.Path(payload_path).write_text(json.dumps(payload))
PY

  local response
  response="$(curl -fsS -X POST "$BASE_URL/v1/execute" -H 'Content-Type: application/json' --data-binary @"$payload_file")"
  local receipt_path public_key_path summary_path execution_id
  receipt_path="$(printf '%s' "$response" | jq -r '.receipt_path')"
  public_key_path="$(printf '%s' "$response" | jq -r '.receipt_public_key_path')"
  summary_path="$(printf '%s' "$response" | jq -r '.receipt_summary_path')"
  execution_id="$(printf '%s' "$response" | jq -r '.execution_id')"

  if [[ -z "$receipt_path" || "$receipt_path" == "null" ]]; then
    echo "FAIL $label missing receipt_path" >&2
    printf '%s
' "$response" >&2
    return 1
  fi

  for path in "$receipt_path" "$public_key_path" "$summary_path"; do
    local retries=20
    until [[ -f "$path" ]] || [[ $retries -eq 0 ]]; do
      sleep 0.1
      retries=$((retries - 1))
    done
    if [[ ! -f "$path" ]]; then
      echo "FAIL $label missing proof file: $path" >&2
      return 1
    fi
  done

  local verify_output
  verify_output="$(cd "$HOME/aegis" && "${CLI_CMD[@]}" receipt verify --file "$receipt_path" --public-key "$public_key_path")"
  printf '=== %s (%s) ===
' "$label" "$execution_id"
  printf '%s
' "$verify_output"

  grep -q '^verification=verified$' <<<"$verify_output"
  grep -q "^divergence_verdict=${expected_verdict}$" <<<"$verify_output"
  grep -q "^artifact_count=${expected_artifacts}$" <<<"$verify_output"
}

allowed_exec="$(new_exec_id)"
cat > "$TMPDIR/allowed.intent.json" <<JSON
{
  "version": "v1",
  "execution_id": "$allowed_exec",
  "workflow_id": "wf_phase6_allowed",
  "task_class": "demo_allowed",
  "declared_purpose": "Emit a clean proof artifact",
  "language": "python",
  "resource_scope": {"workspace_root": "/workspace", "read_paths": ["/workspace"], "write_paths": ["/workspace"], "deny_paths": [], "max_distinct_files": 4},
  "network_scope": {"allow_network": false, "allowed_domains": [], "allowed_ips": [], "max_dns_queries": 0, "max_outbound_conns": 0},
  "process_scope": {"allowed_binaries": ["python3"], "allow_shell": false, "allow_package_install": false, "max_child_processes": 2},
  "broker_scope": {"allowed_delegations": [], "require_host_consent": false},
  "budgets": {"timeout_sec": 8, "memory_mb": 128, "cpu_quota": 100, "stdout_bytes": 4096}
}
JSON
cat > "$TMPDIR/allowed.py" <<'PY'
print("phase6-proof")
PY

network_exec="$(new_exec_id)"
cat > "$TMPDIR/network.intent.json" <<JSON
{
  "version": "v1",
  "execution_id": "$network_exec",
  "workflow_id": "wf_phase6_network",
  "task_class": "demo_network_denied",
  "declared_purpose": "Attempt denied network connect",
  "language": "python",
  "resource_scope": {"workspace_root": "/workspace", "read_paths": ["/workspace"], "write_paths": ["/workspace"], "deny_paths": [], "max_distinct_files": 4},
  "network_scope": {"allow_network": false, "allowed_domains": [], "allowed_ips": [], "max_dns_queries": 0, "max_outbound_conns": 0},
  "process_scope": {"allowed_binaries": ["python3"], "allow_shell": false, "allow_package_install": false, "max_child_processes": 2},
  "broker_scope": {"allowed_delegations": [], "require_host_consent": false},
  "budgets": {"timeout_sec": 8, "memory_mb": 128, "cpu_quota": 100, "stdout_bytes": 4096}
}
JSON
cat > "$TMPDIR/network.py" <<'PY'
import socket
sock = socket.socket()
sock.settimeout(0.2)
try:
    sock.connect(("1.1.1.1", 53))
except Exception:
    pass
print("network-attempted")
PY

path_exec="$(new_exec_id)"
cat > "$TMPDIR/path.intent.json" <<JSON
{
  "version": "v1",
  "execution_id": "$path_exec",
  "workflow_id": "wf_phase6_path",
  "task_class": "demo_path_scan",
  "declared_purpose": "Read a single declared workspace target",
  "language": "python",
  "resource_scope": {"workspace_root": "/workspace", "read_paths": ["/workspace/target.txt"], "write_paths": ["/workspace"], "deny_paths": ["/etc", "/proc"], "max_distinct_files": 5},
  "network_scope": {"allow_network": false, "allowed_domains": [], "allowed_ips": [], "max_dns_queries": 0, "max_outbound_conns": 0},
  "process_scope": {"allowed_binaries": ["python3"], "allow_shell": false, "allow_package_install": false, "max_child_processes": 2},
  "broker_scope": {"allowed_delegations": [], "require_host_consent": false},
  "budgets": {"timeout_sec": 8, "memory_mb": 128, "cpu_quota": 100, "stdout_bytes": 4096}
}
JSON
cat > "$TMPDIR/path.py" <<'PY'
for path in ("/etc/hosts", "/etc/passwd", "/proc/version"):
    try:
        open(path).read()
    except Exception:
        pass
print("path-probed")
PY

shell_exec="$(new_exec_id)"
cat > "$TMPDIR/shell.intent.json" <<JSON
{
  "version": "v1",
  "execution_id": "$shell_exec",
  "workflow_id": "wf_phase6_shell",
  "task_class": "demo_shell_misuse",
  "declared_purpose": "Run Python only",
  "language": "python",
  "resource_scope": {"workspace_root": "/workspace", "read_paths": ["/workspace"], "write_paths": ["/workspace"], "deny_paths": [], "max_distinct_files": 4},
  "network_scope": {"allow_network": false, "allowed_domains": [], "allowed_ips": [], "max_dns_queries": 0, "max_outbound_conns": 0},
  "process_scope": {"allowed_binaries": ["python3"], "allow_shell": false, "allow_package_install": false, "max_child_processes": 2},
  "broker_scope": {"allowed_delegations": [], "require_host_consent": false},
  "budgets": {"timeout_sec": 8, "memory_mb": 128, "cpu_quota": 100, "stdout_bytes": 4096}
}
JSON
cat > "$TMPDIR/shell.py" <<'PY'
import subprocess
subprocess.run(["/bin/sh", "-lc", "echo shell"], check=False)
print("shell-attempted")
PY

run_case allowed python "$TMPDIR/allowed.py" "$TMPDIR/allowed.intent.json" allow 2
run_case network_denied python "$TMPDIR/network.py" "$TMPDIR/network.intent.json" kill_candidate 2
run_case path_probe python "$TMPDIR/path.py" "$TMPDIR/path.intent.json" warn 2
run_case shell_misuse python "$TMPDIR/shell.py" "$TMPDIR/shell.intent.json" kill_candidate 2

echo "run-proof-demo.sh passed"
