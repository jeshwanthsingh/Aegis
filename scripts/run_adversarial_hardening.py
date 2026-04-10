#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.request
from pathlib import Path


REPO = Path("/home/cellardoor/aegis")
BASE_URL = os.environ.get("AEGIS_BASE_URL", "http://127.0.0.1:8080")
AEGIS = REPO / ".aegis/bin/aegis"
LOG_PATH = Path("/tmp/aegis-local-orchestrator.log")


def main() -> int:
    start_orchestrator()
    results = []
    results.append(test_symlink_race())
    results.append(test_telemetry_flood())
    results.extend(test_resource_exhaustion())
    results.extend(test_artifact_tampering())
    results.append(test_ghost_artifact_injection())
    results.append(test_config_mount_protection())
    results.append(test_stream_parity())
    results.append(test_broker_regression())
    print(json.dumps(results, indent=2))
    return 0 if all(item["pass"] for item in results) else 1


def start_orchestrator() -> None:
    subprocess.run(["bash", "-lc", "cd ~/aegis && ./scripts/start-local-orchestrator.sh"], check=True)


def execute(payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        BASE_URL + "/v1/execute",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.loads(response.read().decode("utf-8"))


def execute_stream(payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        BASE_URL + "/v1/execute/stream",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    proof = None
    done = None
    chunks: list[dict] = []
    with urllib.request.urlopen(request, timeout=90) as response:
        for raw_line in response:
            line = raw_line.decode("utf-8").strip()
            if not line.startswith("data: "):
                continue
            chunk = json.loads(line[6:])
            chunks.append(chunk)
            if chunk.get("type") == "proof":
                proof = chunk
            if chunk.get("type") == "done":
                done = chunk
                break
    return {"proof": proof, "done": done, "chunks": chunks}


def health() -> dict:
    with urllib.request.urlopen(BASE_URL + "/health", timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def verify_bundle(proof_dir: str) -> subprocess.CompletedProcess[str]:
    command = f"cd ~/aegis && ./.aegis/bin/aegis receipt verify --proof-dir {proof_dir}"
    return subprocess.run(["bash", "-lc", command], capture_output=True, text=True)


def bundle_statement(proof_dir: str) -> dict:
    receipt_path = Path(proof_dir) / "receipt.dsse.json"
    envelope = json.loads(receipt_path.read_text())
    payload = base64.b64decode(envelope["envelope"]["payload"])
    return json.loads(payload)


def intent(
    execution_id: str,
    language: str,
    read_paths: list[str],
    write_paths: list[str],
    allowed_binaries: list[str],
    timeout_sec: int = 10,
    *,
    allow_network: bool = False,
    allowed_domains: list[str] | None = None,
    allowed_ips: list[str] | None = None,
    max_outbound_conns: int = 0,
    allowed_delegations: list[str] | None = None,
    broker_allowed_domains: list[str] | None = None,
) -> dict:
    return {
        "version": "v1",
        "execution_id": execution_id,
        "workflow_id": f"wf_{execution_id[:8]}",
        "task_class": "adversarial",
        "declared_purpose": "adversarial hardening",
        "language": language,
        "resource_scope": {
            "workspace_root": "/workspace",
            "read_paths": read_paths,
            "write_paths": write_paths,
            "deny_paths": [],
            "max_distinct_files": 256,
        },
        "network_scope": {
            "allow_network": allow_network,
            "allowed_domains": allowed_domains or [],
            "allowed_ips": allowed_ips or [],
            "max_dns_queries": 0,
            "max_outbound_conns": max_outbound_conns,
        },
        "process_scope": {
            "allowed_binaries": allowed_binaries,
            "allow_shell": language == "bash",
            "allow_package_install": False,
            "max_child_processes": 64,
        },
        "broker_scope": {
            "allowed_delegations": allowed_delegations or [],
            "allowed_domains": broker_allowed_domains or [],
            "allowed_action_types": [],
            "require_host_consent": False,
        },
        "budgets": {
            "timeout_sec": timeout_sec,
            "memory_mb": 128,
            "cpu_quota": 100,
            "stdout_bytes": 65536,
        },
    }


def log_for_execution(execution_id: str) -> str:
    if not LOG_PATH.exists():
        return ""
    return "\n".join(
        line for line in LOG_PATH.read_text().splitlines() if execution_id in line
    )


def artifact_names(proof_dir: str) -> list[str]:
    ignored = {"receipt.dsse.json", "receipt.pub", "receipt.summary.txt"}
    return sorted(path.name for path in Path(proof_dir).iterdir() if path.is_file() and path.name not in ignored)


def copy_bundle(proof_dir: str) -> Path:
    dst = Path(tempfile.mkdtemp(prefix="aegis-proof-")) / "bundle"
    shutil.copytree(proof_dir, dst)
    return dst


def test_symlink_race() -> dict:
    execution_id = str(uuid.uuid4())
    payload = {
        "execution_id": execution_id,
        "lang": "bash",
        "code": """set -eu
rm -f /tmp/allowed.txt /tmp/link
printf 'allowed\n' >/tmp/allowed.txt
ln -sfn /tmp/allowed.txt /tmp/link
(
  i=0
  while [ "$i" -lt 12000 ]; do
    ln -sfn /etc/passwd /tmp/link
    ln -sfn /tmp/allowed.txt /tmp/link
    i=$((i+1))
  done
) &
swapper=$!
i=0
while [ "$i" -lt 12000 ]; do
  if IFS= read -r line < /tmp/link; then
    case "$line" in
      root:*) echo SYMLINK_BYPASS:$line; break ;;
    esac
  fi
  i=$((i+1))
done
wait $swapper || :
""",
        "timeout_ms": 10000,
        "intent": intent(execution_id, "bash", ["/tmp", "/etc", "/usr/share/locale", "/dev"], ["/tmp", "/dev/tty"], ["bash", "ln", "rm"]),
    }
    result = execute(payload)
    log_excerpt = log_for_execution(execution_id)
    passed = "SYMLINK_BYPASS:" not in result.get("stdout", "") and "blocked-symlink-open" in log_excerpt
    return {
        "category": "toctou_symlink_race",
        "severity_target": "blocker",
        "tried": "repeatedly swapped /tmp/link between /tmp/allowed.txt and /etc/passwd while reading the alias",
        "pass": passed,
        "execution_id": execution_id,
        "stdout": result.get("stdout", ""),
        "exit_code": result.get("exit_code"),
        "log_signal": "blocked-symlink-open" in log_excerpt,
    }


def test_telemetry_flood() -> dict:
    execution_id = str(uuid.uuid4())
    payload = {
        "execution_id": execution_id,
        "lang": "bash",
        "code": """set -eu
i=0
while [ "$i" -lt 50000 ]; do
  if IFS= read -r line < /etc/hosts; then :; fi
  i=$((i+1))
done
""",
        "timeout_ms": 4000,
        "intent": intent(execution_id, "bash", ["/etc", "/usr/share/locale", "/dev"], ["/dev/tty"], ["bash"]),
    }
    result = execute(payload)
    post_health = health()
    log_excerpt = log_for_execution(execution_id)
    passed = post_health.get("status") == "ok" and (
        "telemetry buffer full" in log_excerpt
        or '"flood_detected":true' in log_excerpt
        or '"dropped":' in log_excerpt
    )
    return {
        "category": "telemetry_vsock_flood",
        "severity_target": "blocker",
        "tried": "tight bounded read-open loop intended to overwhelm runtime event and telemetry buffering",
        "pass": passed,
        "execution_id": execution_id,
        "exit_code": result.get("exit_code"),
        "health_status": post_health.get("status"),
        "drop_signal": "telemetry buffer full" in log_excerpt or '"dropped":' in log_excerpt,
    }


def test_resource_exhaustion() -> list[dict]:
    results = []

    cpu_execution_id = str(uuid.uuid4())
    cpu_result = execute(
        {
            "execution_id": cpu_execution_id,
            "lang": "python",
            "code": "while True:\n    pass\n",
            "timeout_ms": 1500,
        }
    )
    results.append(
        {
            "category": "resource_exhaustion_cpu",
            "severity_target": "blocker",
            "tried": "unbounded CPU spin in Python",
            "pass": health().get("status") == "ok" and cpu_result.get("exit_code") != 0,
            "execution_id": cpu_execution_id,
            "exit_code": cpu_result.get("exit_code"),
            "exit_reason": cpu_result.get("exit_reason"),
        }
    )

    mem_execution_id = str(uuid.uuid4())
    mem_result = execute(
        {
            "execution_id": mem_execution_id,
            "lang": "python",
            "code": "chunks=[]\nwhile True:\n    chunks.append('x'*1024*1024)\n",
            "timeout_ms": 4000,
        }
    )
    results.append(
        {
            "category": "resource_exhaustion_memory",
            "severity_target": "blocker",
            "tried": "append 1 MiB strings until memory exhaustion",
            "pass": health().get("status") == "ok" and mem_result.get("exit_code") != 0,
            "execution_id": mem_execution_id,
            "exit_code": mem_result.get("exit_code"),
            "exit_reason": mem_result.get("exit_reason"),
        }
    )
    return results


def test_artifact_tampering() -> list[dict]:
    execution_id = str(uuid.uuid4())
    result = execute(
        {
            "execution_id": execution_id,
            "lang": "bash",
            "code": "echo integrity-check",
            "timeout_ms": 5000,
        }
    )
    proof_dir = result["proof_dir"]

    receipt_copy = copy_bundle(proof_dir)
    receipt_path = receipt_copy / "receipt.dsse.json"
    data = bytearray(receipt_path.read_bytes())
    data[min(20, len(data) - 1)] ^= 1
    receipt_path.write_bytes(data)
    receipt_verify = verify_bundle(str(receipt_copy))

    manifest_copy = copy_bundle(proof_dir)
    manifest_path = manifest_copy / "output-manifest.json"
    data = bytearray(manifest_path.read_bytes())
    data[min(10, len(data) - 1)] ^= 1
    manifest_path.write_bytes(data)
    manifest_verify = verify_bundle(str(manifest_copy))

    return [
        {
            "category": "artifact_tampering_receipt",
            "severity_target": "blocker",
            "tried": "flipped one byte in receipt.dsse.json and reran public proof verification",
            "pass": receipt_verify.returncode != 0,
            "proof_dir": str(receipt_copy),
            "stderr": receipt_verify.stderr,
        },
        {
            "category": "artifact_tampering_manifest",
            "severity_target": "blocker",
            "tried": "flipped one byte in output-manifest.json and reran public proof verification",
            "pass": manifest_verify.returncode != 0,
            "proof_dir": str(manifest_copy),
            "stderr": manifest_verify.stderr,
        },
    ]


def test_ghost_artifact_injection() -> dict:
    execution_id = str(uuid.uuid4())
    result = execute(
        {
            "execution_id": execution_id,
            "lang": "bash",
            "code": "echo ghost-check",
            "timeout_ms": 5000,
        }
    )
    bundle_copy = copy_bundle(result["proof_dir"])
    (bundle_copy / "ghost.txt").write_text("ghost\n")
    verify = verify_bundle(str(bundle_copy))
    return {
        "category": "ghost_artifact_injection",
        "severity_target": "high",
        "tried": "added an undeclared ghost.txt file to a copied proof bundle and reran public proof verification",
        "pass": verify.returncode != 0,
        "proof_dir": str(bundle_copy),
        "stderr": verify.stderr,
    }


def test_config_mount_protection() -> dict:
    execution_id = str(uuid.uuid4())
    result = execute(
        {
            "execution_id": execution_id,
            "lang": "bash",
            "code": "printf 'tamper' >> /etc/aegis-guest-runner.json",
            "timeout_ms": 5000,
            "intent": intent(execution_id, "bash", ["/etc", "/usr/share/locale", "/dev"], ["/dev/tty"], ["bash"]),
        }
    )
    stderr = result.get("stderr", "")
    return {
        "category": "configuration_mount_protection",
        "severity_target": "medium",
        "tried": "attempted guest-side append to /etc/aegis-guest-runner.json",
        "pass": "Read-only file system" in stderr or "Permission denied" in stderr or result.get("exit_code") != 0,
        "execution_id": execution_id,
        "stderr": stderr,
        "exit_code": result.get("exit_code"),
    }


def test_stream_parity() -> dict:
    code = "echo parity-check"
    sync_result = execute({"execution_id": str(uuid.uuid4()), "lang": "bash", "code": code, "timeout_ms": 5000})
    stream_result = execute_stream({"execution_id": str(uuid.uuid4()), "lang": "bash", "code": code, "timeout_ms": 5000})
    if "proof_dir" not in sync_result or sync_result.get("error"):
        return {
            "category": "stream_nonstream_parity",
            "severity_target": "medium",
            "tried": "ran the same bash workload through /v1/execute and /v1/execute/stream and compared proof semantics",
            "pass": False,
            "sync_error": sync_result.get("error", "missing proof_dir"),
            "sync_result": sync_result,
        }
    if not stream_result.get("proof") or not stream_result.get("done"):
        return {
            "category": "stream_nonstream_parity",
            "severity_target": "medium",
            "tried": "ran the same bash workload through /v1/execute and /v1/execute/stream and compared proof semantics",
            "pass": False,
            "stream_error": "missing proof or done chunk",
            "stream_result": stream_result,
        }
    sync_statement = bundle_statement(sync_result["proof_dir"])
    stream_statement = bundle_statement(stream_result["proof"]["proof_dir"])
    sync_subjects = sorted(subject["name"] for subject in sync_statement["subject"])
    stream_subjects = sorted(subject["name"] for subject in stream_statement["subject"])
    pass_result = (
        sync_result.get("exit_code") == stream_result["done"].get("exit_code")
        and sync_result.get("exit_reason") == stream_result["done"].get("reason")
        and sync_subjects == stream_subjects
        and sync_statement["predicate"]["divergence"]["verdict"] == stream_statement["predicate"]["divergence"]["verdict"]
    )
    return {
        "category": "stream_nonstream_parity",
        "severity_target": "medium",
        "tried": "ran the same bash workload through /v1/execute and /v1/execute/stream and compared proof semantics",
        "pass": pass_result,
        "sync_subjects": sync_subjects,
        "stream_subjects": stream_subjects,
        "sync_exit_reason": sync_result.get("exit_reason"),
        "stream_exit_reason": stream_result["done"].get("reason"),
        "sync_result": sync_result,
        "stream_done": stream_result["done"],
    }


def test_broker_regression() -> dict:
    execution_id = str(uuid.uuid4())
    payload = {
        "execution_id": execution_id,
        "lang": "bash",
        "code": """set -euo pipefail
exec 3<>/dev/tcp/127.0.0.1/8888
printf 'GET http://127.0.0.1:1/probe HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n' >&3
response=''
while IFS= read -r line <&3; do
  response+="$line"$'\\n'
done || true
exec 3>&-
exec 3<&-
case "$response" in
  *'HTTP/1.1 403'*'broker denied:'*|*'HTTP/1.0 403'*'broker denied:'*)
    echo PASS_denied_no_raw_token
    exit 0
    ;;
esac
echo FAIL_broker_denied
printf '%s\\n' "$response"
exit 1
""",
        "timeout_ms": 10000,
        "intent": intent(
            execution_id,
            "bash",
            ["/workspace", "/etc", "/usr/share/locale", "/dev"],
            ["/workspace", "/dev/tty"],
            ["bash"],
            allow_network=True,
            allowed_ips=["127.0.0.1"],
            max_outbound_conns=1,
            allowed_delegations=["github"],
            broker_allowed_domains=["example.invalid"],
        ),
    }
    result = execute(payload)
    receipt_summary = ""
    if result.get("receipt_summary_path"):
        receipt_summary = Path(result["receipt_summary_path"]).read_text(errors="replace")
    return {
        "category": "broker_regression_denied_path",
        "severity_target": "medium",
        "tried": "ran a real broker-capable denied-path execution and verified denial without raw secret exposure",
        "pass": "PASS_denied_no_raw_token" in result.get("stdout", "") and "broker.request_denied" in receipt_summary,
        "execution_id": execution_id,
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
        "receipt_summary_path": result.get("receipt_summary_path"),
    }


if __name__ == "__main__":
    sys.exit(main())
