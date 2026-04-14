#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlparse
import urllib.request
import uuid


REPO_DIR = Path(__file__).resolve().parents[1]
BASE_URL = os.environ.get("AEGIS_BASE_URL", os.environ.get("AEGIS_URL", "http://localhost:8080")).rstrip("/")
RECEIVER_URL = os.environ.get("RECEIVER_URL", "http://127.0.0.1:8081")
CLI_BIN = REPO_DIR / ".aegis" / "bin" / "aegis"
API_KEY = os.environ.get("AEGIS_API_KEY", "").strip()
EXPECTED_LINES = (
    "verification=verified",
    "denial_marker=direct_egress_denied",
    "denial_rule_id=governance.direct_egress_disabled",
)


def receiver_host_port() -> tuple[str, int]:
    parsed = urlparse(RECEIVER_URL)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8081
    return host, port


def execute_code() -> str:
    host, port = receiver_host_port()
    return f"""import os, socket

s = socket.socket()
s.settimeout(2)
try:
    rc = s.connect_ex(({host!r}, {port}))
    if rc == 0:
        msg = "BAD: connected\\n"
        exit_code = 1
    else:
        msg = f"GOOD: blocked errno={{rc}}\\n"
        exit_code = 0
except Exception as exc:
    msg = f"GOOD: blocked {{type(exc).__name__}}: {{exc}}\\n"
    exit_code = 0
finally:
    try:
        s.close()
    except Exception:
        pass
os.write(1, msg.encode())
if exit_code == 0:
    print("EXFIL_FAILED")
raise SystemExit(exit_code)
"""


def execute_intent(execution_id: str) -> dict[str, object]:
    return {
        "version": "v1",
        "execution_id": execution_id,
        "workflow_id": "wf_demo_exfil_v1",
        "task_class": "demo_exfil_aegis",
        "declared_purpose": "Prove denied direct loopback exfiltration with receipt evidence",
        "language": "python",
        "resource_scope": {
            "workspace_root": "/workspace",
            "read_paths": ["/workspace", "/etc", "/usr/share/locale", "/dev"],
            "write_paths": ["/workspace", "/dev/tty"],
            "deny_paths": [],
            "max_distinct_files": 64,
        },
        "network_scope": {
            "allow_network": False,
            "allowed_domains": [],
            "allowed_ips": [],
            "max_dns_queries": 0,
            "max_outbound_conns": 1,
        },
        "process_scope": {
            "allowed_binaries": ["python3"],
            "allow_shell": False,
            "allow_package_install": False,
            "max_child_processes": 6,
        },
        "broker_scope": {
            "allowed_delegations": [],
            "allowed_domains": [],
            "allowed_action_types": [],
            "require_host_consent": False,
        },
        "budgets": {
            "timeout_sec": 10,
            "memory_mb": 128,
            "cpu_quota": 100,
            "stdout_bytes": 4096,
        },
    }


def execute_payload() -> dict[str, object]:
    execution_id = str(uuid.uuid4())
    return {
        "execution_id": execution_id,
        "lang": "python",
        "code": execute_code(),
        "timeout_ms": 8000,
        "profile": "standard",
        "intent": execute_intent(execution_id),
    }


def post_execute(payload: dict[str, object]) -> dict[str, object]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(f"{BASE_URL}/v1/execute", data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    if API_KEY:
        request.add_header("Authorization", f"Bearer {API_KEY}")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def verify_receipt(proof_dir: str) -> str:
    if not CLI_BIN.is_file():
        raise RuntimeError(f"missing repo-local CLI at {CLI_BIN}")
    result = subprocess.run(
        [str(CLI_BIN), "receipt", "verify", "--proof-dir", proof_dir],
        cwd=REPO_DIR,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def require_line(output: str, line: str) -> None:
    if line not in output:
        raise RuntimeError(f"missing {line!r} in verifier output:\n{output}")


def main() -> int:
    response = post_execute(execute_payload())
    stdout = str(response.get("stdout", ""))
    if "EXFIL_FAILED" not in stdout:
        raise RuntimeError(f"unexpected execution stdout: {stdout!r}")
    proof_dir = str(response.get("proof_dir", "")).strip()
    if not proof_dir:
        raise RuntimeError(f"missing proof_dir in response: {response}")
    verify_output = verify_receipt(proof_dir)
    for line in EXPECTED_LINES:
        require_line(verify_output, line)
    print("EXFIL_FAILED")
    for line in EXPECTED_LINES:
        print(line)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"status=failed error={exc}", file=sys.stderr)
        raise SystemExit(1)
