#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parents[1]
STATE_DIR = Path("/tmp/aegis-demo")
STATE_PATH = STATE_DIR / "state.json"
RUNTIME_LOG = STATE_DIR / "orchestrator.log"
POSTGRES_LOG = STATE_DIR / "postgres.log"
POSTGRES_DATA = STATE_DIR / "postgres-data"
POSTGRES_SOCKET = STATE_DIR / "postgres-socket"
PROOF_ROOT = STATE_DIR / "proofs"
ARTIFACTS_ROOT = STATE_DIR / "artifacts"
HOST_REPOS_ROOT = STATE_DIR / "host-repos"
DEMO_REPO_DIR = HOST_REPOS_ROOT / "demo-repo"
APPROVAL_SEED_PATH = STATE_DIR / "approval_signing_seed.b64"
LEASE_SEED_PATH = STATE_DIR / "lease_signing_seed.b64"
CONFIG_PATH = REPO_DIR / ".aegis" / "config.yaml"
CLI_BIN = REPO_DIR / ".aegis" / "bin" / "aegis"
ORCH_BIN = REPO_DIR / ".aegis" / "bin" / "orchestrator"
POLICY_PATH = REPO_DIR / "configs" / "default-policy.yaml"
SCHEMA_PATH = REPO_DIR / "db" / "schema.sql"
ASSETS_DIR = REPO_DIR / "assets"
KERNEL_PATH = ASSETS_DIR / "vmlinux"
ROOTFS_PATH = ASSETS_DIR / "alpine-base.ext4"
DEFAULT_API_URL = "http://127.0.0.1:8080"
DEFAULT_ADDR = "127.0.0.1:8080"
DEFAULT_TIMEOUT_MS = 10000
DEFAULT_DB_NAME = "aegisdemo"
DEFAULT_DB_USER = "aegisdemo"
DEFAULT_BROKER_TOKEN = "aegis-demo-token"
DEFAULT_APPROVAL_TTL = "5m"
DEMO_REPO_LABEL = "demo"
PROOF_RE = re.compile(r"^\[proof bundle (.+)\]$")


@dataclass(slots=True)
class DemoState:
    api_url: str
    addr: str
    runtime_pid: int
    runtime_log: str
    postgres_data_dir: str
    postgres_log: str
    postgres_port: int
    postgres_user: str
    postgres_db: str
    postgres_url: str
    proof_root: str
    broker_binding: str

    def to_dict(self) -> dict[str, object]:
        return {
            "api_url": self.api_url,
            "addr": self.addr,
            "runtime_pid": self.runtime_pid,
            "runtime_log": self.runtime_log,
            "postgres_data_dir": self.postgres_data_dir,
            "postgres_log": self.postgres_log,
            "postgres_port": self.postgres_port,
            "postgres_user": self.postgres_user,
            "postgres_db": self.postgres_db,
            "postgres_url": self.postgres_url,
            "proof_root": self.proof_root,
            "broker_binding": self.broker_binding,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> "DemoState":
        return cls(
            api_url=str(raw["api_url"]),
            addr=str(raw["addr"]),
            runtime_pid=int(raw["runtime_pid"]),
            runtime_log=str(raw["runtime_log"]),
            postgres_data_dir=str(raw["postgres_data_dir"]),
            postgres_log=str(raw["postgres_log"]),
            postgres_port=int(raw["postgres_port"]),
            postgres_user=str(raw["postgres_user"]),
            postgres_db=str(raw["postgres_db"]),
            postgres_url=str(raw["postgres_url"]),
            proof_root=str(raw["proof_root"]),
            broker_binding=str(raw.get("broker_binding", "demo")),
        )


@dataclass(slots=True)
class ProbeObservation:
    path: str
    auth_present: bool


class ProbeServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self) -> None:
        self.observations: list[ProbeObservation] = []
        super().__init__(("127.0.0.1", 0), ProbeHandler)

    @property
    def port(self) -> int:
        return int(self.server_address[1])


class ProbeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        auth_header = self.headers.get("Authorization", "")
        auth_present = auth_header.startswith("Bearer ")
        self.server.observations.append(  # type: ignore[attr-defined]
            ProbeObservation(path=self.path, auth_present=auth_present)
        )
        body = f"auth_present={'true' if auth_present else 'false'}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class ProbeContext:
    def __init__(self) -> None:
        self.server = ProbeServer()
        self._thread = None

    def __enter__(self) -> ProbeServer:
        import threading

        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return self.server

    def __exit__(self, exc_type, exc, tb) -> None:
        self.server.shutdown()
        self.server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aegis local demo helper")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("up", help="bootstrap and start a localhost demo runtime")
    sub.add_parser("down", help="stop the local demo runtime")
    sub.add_parser("status", help="show the local demo runtime status")
    sub.add_parser("preflight", help="check visible demo prerequisites and bootstrap state")
    sub.add_parser("clean", help="run the clean execution demo")
    sub.add_parser("exfil-denied", help="run the exfil denied demo")
    sub.add_parser("broker-success", help="run the brokered outbound success demo")
    sub.add_parser("escalation-termination", help="run canonical Demo A: escalation termination")
    sub.add_parser("host-patch-denied", help="run canonical Demo B: host patch denied")
    sub.add_parser("host-patch-approved", help="run canonical Demo C: host patch approved")
    sub.add_parser("broker-http", help="run canonical Demo D: brokered HTTP")
    sub.add_parser("canonical-suite", help="run demos A-D sequentially")
    args = parser.parse_args()

    try:
        if args.command == "up":
            return demo_up()
        if args.command == "down":
            return demo_down()
        if args.command == "status":
            return demo_status()
        if args.command == "preflight":
            return demo_preflight()
        if args.command == "clean":
            return demo_clean()
        if args.command == "exfil-denied":
            return demo_exfil_denied()
        if args.command == "broker-success":
            return demo_broker_success()
        if args.command == "escalation-termination":
            return demo_escalation_termination()
        if args.command == "host-patch-denied":
            return demo_host_patch_denied()
        if args.command == "host-patch-approved":
            return demo_host_patch_approved()
        if args.command == "broker-http":
            return demo_broker_http()
        if args.command == "canonical-suite":
            return demo_canonical_suite()
    except DemoError as exc:
        print(f"demo error: {exc}", file=sys.stderr)
        return 1
    return 2


class DemoError(RuntimeError):
    pass


def demo_up() -> int:
    if runtime_health(DEFAULT_API_URL):
        state = load_state()
        if state is not None:
            print(f"status=running")
            print(f"api_url={state.api_url}")
            print(f"runtime_log={state.runtime_log}")
            print(f"postgres_url={state.postgres_url}")
            print(f"artifacts_root={ARTIFACTS_ROOT}")
            print(f"demo_repo_dir={DEMO_REPO_DIR}")
            print_next_steps()
            return 0
        raise DemoError(
            f"Aegis is already healthy at {DEFAULT_API_URL} but is not owned by the demo state at {STATE_PATH}. "
            "Reuse that runtime or stop it before running demo_up.sh."
        )

    cleanup_from_state()
    cleanup_legacy_runtime_inputs()
    require_preflight()
    ensure_demo_seed(APPROVAL_SEED_PATH)
    ensure_demo_seed(LEASE_SEED_PATH)
    ensure_demo_repo_baseline()
    state = start_demo_runtime()
    save_state(state)
    print("status=started")
    print(f"api_url={state.api_url}")
    print(f"runtime_log={state.runtime_log}")
    print(f"postgres_url={state.postgres_url}")
    print(f"proof_root={state.proof_root}")
    print(f"artifacts_root={ARTIFACTS_ROOT}")
    print(f"demo_repo_dir={DEMO_REPO_DIR}")
    print_next_steps()
    return 0


def demo_down() -> int:
    state = load_state()
    cleanup_legacy_runtime_inputs()
    if state is None:
        print("status=not_running")
        print(f"state_file={STATE_PATH}")
        return 0
    stop_runtime(state)
    stop_postgres(state)
    try:
        STATE_PATH.unlink()
    except FileNotFoundError:
        pass
    print("status=stopped")
    print(f"runtime_log={state.runtime_log}")
    print(f"postgres_log={state.postgres_log}")
    return 0


def demo_status() -> int:
    state = load_state()
    healthy = runtime_health(DEFAULT_API_URL)
    if state is None:
        print("status=not_running")
        print(f"api_url={DEFAULT_API_URL}")
        return 0
    print(f"status={'running' if healthy else 'degraded'}")
    print(f"api_url={state.api_url}")
    print(f"runtime_pid={state.runtime_pid}")
    print(f"runtime_log={state.runtime_log}")
    print(f"postgres_url={state.postgres_url}")
    print(f"postgres_log={state.postgres_log}")
    print(f"proof_root={state.proof_root}")
    print(f"artifacts_root={ARTIFACTS_ROOT}")
    print(f"demo_repo_dir={DEMO_REPO_DIR}")
    return 0


def demo_preflight() -> int:
    issues = sorted(collect_preflight_issues())
    if len(issues) == 0:
        print("status=ok")
        print(f"config_path={CONFIG_PATH}")
        print(f"cli_bin={CLI_BIN}")
        print(f"orchestrator_bin={ORCH_BIN}")
        print(f"receipt_signing_seed={REPO_DIR / '.aegis' / 'receipt_signing_seed.b64'}")
        return 0
    print("status=failed")
    print(f"missing_count={len(issues)}")
    for idx, issue in enumerate(issues, start=1):
        print(f"missing_{idx}={issue}")
    return 1


def demo_clean() -> int:
    ensure_runtime_running()
    result = run_cli_demo(
        label="clean_execution",
        run_args=["run", "--lang", "bash", "--timeout", str(DEFAULT_TIMEOUT_MS), "--code", "echo DEMO_CLEAN_OK"],
        expected_verify={
            "verification": "verified",
            "result_class": "completed",
            "outcome": "completed",
        },
    )
    print_demo_result("clean_execution", result)
    return 0


def demo_exfil_denied() -> int:
    ensure_runtime_running()
    execution_id = str(uuid.uuid4())
    code = """import socket
s = socket.socket()
s.settimeout(2)
try:
    rc = s.connect_ex(("1.2.3.4", 4444))
    print(f"connect_ex_rc={rc}")
except Exception as exc:
    print(f"connect_exc={type(exc).__name__}:{exc}")
finally:
    try:
        s.close()
    except Exception:
        pass
print("DEMO_EXFIL_ATTEMPTED")
"""
    intent = base_intent(
        execution_id=execution_id,
        language="python",
        allow_network=False,
        allowed_ips=[],
        allowed_domains=[],
        allowed_binaries=["python3"],
        allow_shell=False,
        allowed_delegations=[],
        broker_domains=[],
        task_class="demo_exfil_denied",
        declared_purpose="Prove direct outbound exfiltration is denied with signed receipt evidence",
    )
    with tempfile.TemporaryDirectory(prefix="aegis-demo-exfil-") as tmpdir:
        code_path = Path(tmpdir) / "demo.py"
        intent_path = Path(tmpdir) / "intent.json"
        code_path.write_text(code, encoding="utf-8")
        intent_path.write_text(json.dumps(intent), encoding="utf-8")
        result = run_cli_demo(
            label="exfil_denied",
            run_args=["run", "--lang", "python", "--timeout", str(DEFAULT_TIMEOUT_MS), "--file", str(code_path), "--intent-file", str(intent_path)],
            expected_verify={
                "verification": "verified",
                "result_class": "denied",
                "denial_marker": "direct_egress_denied",
            },
            contains_verify=[
                "governed_action_1=kind=network_connect",
                "decision=deny",
            ],
        )
    print_demo_result("exfil_denied", result)
    return 0


def demo_broker_success() -> int:
    ensure_runtime_running()
    execution_id = str(uuid.uuid4())
    with ProbeContext() as probe:
        code = f"""#!/usr/bin/env bash
set -euo pipefail
exec 3<>/dev/tcp/127.0.0.1/8888
printf 'GET http://127.0.0.1:{probe.port}/probe HTTP/1.1\\r\\nHost: 127.0.0.1:{probe.port}\\r\\nConnection: close\\r\\n\\r\\n' >&3
response=''
while IFS= read -r line <&3; do
  response+="$line"$'\\n'
done || true
exec 3>&-
exec 3<&-
printf '%s\\n' "$response"
case "$response" in
  *auth_present=true*)
    echo 'DEMO_BROKER_OK'
    exit 0
    ;;
esac
echo 'DEMO_BROKER_FAILED'
exit 1
"""
        intent = base_intent(
            execution_id=execution_id,
            language="bash",
            allow_network=True,
            allowed_ips=["127.0.0.1"],
            allowed_domains=[],
            allowed_binaries=["bash"],
            allow_shell=True,
            allowed_delegations=["demo"],
            broker_domains=["127.0.0.1", f"127.0.0.1:{probe.port}"],
            task_class="demo_broker_success",
            declared_purpose="Prove brokered outbound HTTP succeeds with signed governed action evidence",
        )
        with tempfile.TemporaryDirectory(prefix="aegis-demo-broker-") as tmpdir:
            code_path = Path(tmpdir) / "demo.sh"
            intent_path = Path(tmpdir) / "intent.json"
            code_path.write_text(code, encoding="utf-8")
            intent_path.write_text(json.dumps(intent), encoding="utf-8")
            result = run_cli_demo(
                label="broker_success",
                run_args=["run", "--lang", "bash", "--timeout", str(DEFAULT_TIMEOUT_MS), "--file", str(code_path), "--intent-file", str(intent_path)],
                expected_verify={
                    "verification": "verified",
                    "result_class": "completed",
                    "broker_allowed_count": "1",
                },
                contains_verify=[
                    "governed_action_1=kind=http_request",
                    "decision=allow",
                    "broker_bindings_used=demo",
                ],
            )
        if len(probe.observations) != 1 or not probe.observations[0].auth_present:
            raise DemoError(f"broker_success probe did not observe exactly one authenticated request: {probe.observations}")
    print_demo_result("broker_success", result)
    return 0


def demo_escalation_termination() -> int:
    ensure_runtime_running()
    execution_id = str(uuid.uuid4())
    artifact_dir = prepare_demo_artifact_dir("demo_a_escalation_termination", execution_id)
    code = """import socket

def probe(host: str) -> None:
    sock = socket.create_connection(("127.0.0.1", 8888), timeout=5)
    try:
        request = f"GET http://{host}/probe HTTP/1.1\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n".encode()
        sock.sendall(request)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        print(response.decode("utf-8", errors="replace"))
    finally:
        sock.close()

for host in ["example.com", "iana.org", "example.org"]:
    probe(host)

print("DEMO_A_ESCALATION_ATTEMPTED")
"""
    intent = base_intent(
        execution_id=execution_id,
        language="python",
        allow_network=True,
        allowed_ips=["127.0.0.1"],
        allowed_domains=[],
        allowed_binaries=["python3"],
        allow_shell=False,
        allowed_delegations=["demo"],
        broker_domains=["127.0.0.1"],
        broker_action_types=["http_request"],
        require_host_consent=False,
        task_class="demo_a_escalation_termination",
        declared_purpose="Prove repeated broker probing becomes terminal escalation evidence",
    )
    code_path, intent_path = write_demo_inputs(artifact_dir, code, intent, language="python")
    result = run_cli_demo(
        label="demo_a_escalation_termination",
        run_args=["run", "--lang", "python", "--timeout", str(DEFAULT_TIMEOUT_MS), "--file", str(code_path), "--intent-file", str(intent_path)],
        expected_run_codes={1},
        expected_verify={"verification": "verified", "runtime_policy_termination_reason": "privilege_escalation_attempt"},
        contains_verify=["repeated_probing_pattern"],
        artifact_dir=artifact_dir,
        status="terminated",
    )
    print_demo_result("demo_a_escalation_termination", result)
    return 0


def demo_host_patch_denied() -> int:
    ensure_runtime_running()
    base_revision = ensure_demo_repo_baseline()
    execution_id = str(uuid.uuid4())
    artifact_dir = prepare_demo_artifact_dir("demo_b_host_patch_denied", execution_id)
    patch_text = demo_repo_patch()
    write_patch_artifact(artifact_dir, patch_text)
    code = host_patch_code_template(patch_text=patch_text, base_revision=base_revision, ticket_slot="")
    intent = base_intent(
        execution_id=execution_id,
        language="python",
        allow_network=False,
        allowed_ips=[],
        allowed_domains=[],
        allowed_binaries=["python3"],
        allow_shell=False,
        allowed_delegations=[],
        broker_domains=[],
        broker_action_types=["host_repo_apply_patch"],
        broker_repo_labels=[DEMO_REPO_LABEL],
        require_host_consent=False,
        task_class="demo_b_host_patch_denied",
        declared_purpose="Prove host_repo_apply_patch is denied without a valid approval ticket",
    )
    code_path, intent_path = write_demo_inputs(artifact_dir, code, intent, language="python")
    result = run_cli_demo(
        label="demo_b_host_patch_denied",
        run_args=["run", "--lang", "python", "--timeout", str(DEFAULT_TIMEOUT_MS), "--file", str(code_path), "--intent-file", str(intent_path)],
        expected_run_codes={1},
        expected_verify={"verification": "verified"},
        contains_verify=[
            "host_action_class=repo_apply_patch_v1",
            "approval_result=missing",
            "lease_result=verified",
        ],
        artifact_dir=artifact_dir,
        status="expected_deny",
    )
    assert_demo_repo_contents("before\n", "demo_b_host_patch_denied")
    print_demo_result("demo_b_host_patch_denied", result)
    return 0


def demo_host_patch_approved() -> int:
    ensure_runtime_running()
    base_revision = ensure_demo_repo_baseline()
    execution_id = str(uuid.uuid4())
    artifact_dir = prepare_demo_artifact_dir("demo_c_host_patch_approved", execution_id)
    patch_text = demo_repo_patch()
    write_patch_artifact(artifact_dir, patch_text)
    template_code = host_patch_code_template(patch_text=patch_text, base_revision=base_revision, ticket_slot=approval_token_slot())
    intent = base_intent(
        execution_id=execution_id,
        language="python",
        allow_network=False,
        allowed_ips=[],
        allowed_domains=[],
        allowed_binaries=["python3"],
        allow_shell=False,
        allowed_delegations=[],
        broker_domains=[],
        broker_action_types=["host_repo_apply_patch"],
        broker_repo_labels=[DEMO_REPO_LABEL],
        require_host_consent=False,
        task_class="demo_c_host_patch_approved",
        declared_purpose="Prove host_repo_apply_patch succeeds exactly once with valid lease and approval",
    )
    template_path, intent_path = write_demo_inputs(artifact_dir, template_code, intent, language="python")
    preview = preview_demo_execution(template_path, intent_path, language="python")
    approval = issue_host_patch_approval(
        execution_id=preview["execution_id"],
        policy_digest=preview["policy_digest"],
        repo_label=DEMO_REPO_LABEL,
        patch_text=patch_text,
        base_revision=base_revision,
        artifact_dir=artifact_dir,
    )
    runtime_code = render_guest_patch_script(template_path, approval_token=approval["approval_ticket_token"])
    result = run_cli_demo(
        label="demo_c_host_patch_approved",
        run_args=["run", "--lang", "python", "--timeout", str(DEFAULT_TIMEOUT_MS), "--code", runtime_code, "--intent-file", str(intent_path)],
        expected_run_codes={0},
        expected_verify={"verification": "verified"},
        contains_verify=[
            "host_action_class=repo_apply_patch_v1",
            "approval_result=verified",
            "lease_result=verified",
            "affected_paths=demo.txt",
        ],
        artifact_dir=artifact_dir,
        status="success",
    )
    assert_demo_repo_contents("after\n", "demo_c_host_patch_approved")
    print_demo_result("demo_c_host_patch_approved", result)
    return 0


def demo_broker_http() -> int:
    ensure_runtime_running()
    execution_id = str(uuid.uuid4())
    artifact_dir = prepare_demo_artifact_dir("demo_d_broker_http", execution_id)
    with ProbeContext() as probe:
        template_code = broker_http_code_template(port=probe.port, ticket_slot=approval_token_slot())
        intent = base_intent(
            execution_id=execution_id,
            language="python",
            allow_network=True,
            allowed_ips=["127.0.0.1"],
            allowed_domains=[],
            allowed_binaries=["python3"],
            allow_shell=False,
            allowed_delegations=["demo"],
            broker_domains=["127.0.0.1", f"127.0.0.1:{probe.port}"],
            broker_action_types=["http_request"],
            require_host_consent=True,
            task_class="demo_d_broker_http",
            declared_purpose="Prove brokered outbound HTTP succeeds with valid lease and approval",
        )
        code_path, intent_path = write_demo_inputs(artifact_dir, template_code, intent, language="python")
        preview = preview_demo_execution(code_path, intent_path, language="python")
        approval = issue_http_approval(
            execution_id=preview["execution_id"],
            policy_digest=preview["policy_digest"],
            method="GET",
            url=f"http://127.0.0.1:{probe.port}/probe",
            artifact_dir=artifact_dir,
        )
        runtime_code = render_guest_broker_http_script(port=probe.port, approval_token=approval["approval_ticket_token"])
        result = run_cli_demo(
            label="demo_d_broker_http",
            run_args=["run", "--lang", "python", "--timeout", str(DEFAULT_TIMEOUT_MS), "--code", runtime_code, "--intent-file", str(intent_path)],
            expected_run_codes={0},
            expected_verify={"verification": "verified", "broker_allowed_count": "1"},
            contains_verify=[
                "approval_result=verified",
                "lease_result=verified",
                "governed_action_1=kind=http_request",
                "broker_bindings_used=demo",
            ],
            artifact_dir=artifact_dir,
            status="success",
        )
        if len(probe.observations) != 1 or not probe.observations[0].auth_present:
            raise DemoError(f"demo_d_broker_http probe did not observe exactly one authenticated request: {probe.observations}")
    print_demo_result("demo_d_broker_http", result)
    return 0


def demo_canonical_suite() -> int:
    demo_escalation_termination()
    demo_host_patch_denied()
    demo_host_patch_approved()
    demo_broker_http()
    return 0


def base_intent(
    *,
    execution_id: str,
    language: str,
    allow_network: bool,
    allowed_ips: list[str],
    allowed_domains: list[str],
    allowed_binaries: list[str],
    allow_shell: bool,
    allowed_delegations: list[str],
    broker_domains: list[str],
    task_class: str,
    declared_purpose: str,
    broker_action_types: list[str] | None = None,
    broker_repo_labels: list[str] | None = None,
    require_host_consent: bool = False,
) -> dict[str, object]:
    return {
        "version": "v1",
        "execution_id": execution_id,
        "workflow_id": "wf_demo_local_v1",
        "task_class": task_class,
        "declared_purpose": declared_purpose,
        "language": language,
        "resource_scope": {
            "workspace_root": "/workspace",
            "read_paths": ["/workspace", "/etc", "/usr/share/locale", "/dev"],
            "write_paths": ["/workspace", "/dev/tty"],
            "deny_paths": [],
            "max_distinct_files": 64,
        },
        "network_scope": {
            "allow_network": allow_network,
            "allowed_domains": allowed_domains,
            "allowed_ips": allowed_ips,
            "max_dns_queries": 0,
            "max_outbound_conns": 1,
        },
        "process_scope": {
            "allowed_binaries": allowed_binaries,
            "allow_shell": allow_shell,
            "allow_package_install": False,
            "max_child_processes": 6,
        },
        "broker_scope": {
            "allowed_delegations": allowed_delegations,
            "allowed_domains": broker_domains,
            "allowed_repo_labels": broker_repo_labels or [],
            "allowed_action_types": broker_action_types or [],
            "require_host_consent": require_host_consent,
        },
        "budgets": {
            "timeout_sec": 10,
            "memory_mb": 128,
            "cpu_quota": 100,
            "stdout_bytes": 4096,
        },
    }


TOKEN_SLOT_WIDTH = 2048
TOKEN_SLOT_PREFIX = "<AEGIS_APPROVAL_TOKEN>"
TOKEN_SLOT_MARKER = TOKEN_SLOT_PREFIX + (" " * (TOKEN_SLOT_WIDTH - len(TOKEN_SLOT_PREFIX)))


def demo_repo_patch() -> str:
    return """--- a/demo.txt
+++ b/demo.txt
@@ -1 +1 @@
-before
+after
"""


def ensure_demo_seed(path: Path) -> str:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    seed = base64.b64encode(os.urandom(32)).decode("ascii")
    path.write_text(seed + "\n", encoding="utf-8")
    path.chmod(0o600)
    return seed


def ensure_demo_repo_baseline() -> str:
    HOST_REPOS_ROOT.mkdir(parents=True, exist_ok=True)
    if DEMO_REPO_DIR.exists():
        shutil.rmtree(DEMO_REPO_DIR)
    DEMO_REPO_DIR.mkdir(parents=True, exist_ok=True)
    subprocess_run(["git", "init", "-b", "main"], cwd=DEMO_REPO_DIR, label="init demo repo")
    subprocess_run(["git", "config", "user.name", "Aegis Demo"], cwd=DEMO_REPO_DIR, label="config demo repo user")
    subprocess_run(["git", "config", "user.email", "demo@aegis.local"], cwd=DEMO_REPO_DIR, label="config demo repo email")
    (DEMO_REPO_DIR / "demo.txt").write_text("before\n", encoding="utf-8")
    subprocess_run(["git", "add", "demo.txt"], cwd=DEMO_REPO_DIR, label="stage demo repo baseline")
    subprocess_run(["git", "commit", "-m", "baseline"], cwd=DEMO_REPO_DIR, label="commit demo repo baseline")
    proc = subprocess_run(["git", "rev-parse", "HEAD"], cwd=DEMO_REPO_DIR, label="resolve demo repo base revision")
    return proc.stdout.strip()


def assert_demo_repo_contents(expected: str, label: str) -> None:
    actual = (DEMO_REPO_DIR / "demo.txt").read_text(encoding="utf-8")
    if actual != expected:
        raise DemoError(f"{label}: demo repo contents mismatch: got {actual!r} want {expected!r}")


def sanitize_demo_label(label: str) -> str:
    lowered = re.sub(r"[^a-z0-9_-]+", "-", label.lower()).strip("-")
    if not lowered:
        raise DemoError(f"invalid demo label {label!r}")
    return lowered


def prepare_demo_artifact_dir(label: str, execution_id: str) -> Path:
    safe_label = sanitize_demo_label(label)
    artifact_dir = ARTIFACTS_ROOT / safe_label / execution_id
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir


def write_demo_inputs(artifact_dir: Path, code: str, intent: dict[str, object], *, language: str) -> tuple[Path, Path]:
    suffix = ".py" if language == "python" else ".sh"
    code_path = artifact_dir / f"code.template{suffix}"
    intent_path = artifact_dir / "intent.json"
    code_path.write_text(code, encoding="utf-8")
    intent_path.write_text(json.dumps(intent, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return code_path, intent_path


def write_patch_artifact(artifact_dir: Path, patch_text: str) -> Path:
    patch_path = artifact_dir / "patch.diff"
    patch_path.write_text(patch_text, encoding="utf-8")
    return patch_path


def approval_token_slot() -> str:
    return TOKEN_SLOT_MARKER


def inject_approval_token(template: str, approval_token: str) -> str:
    if len(approval_token) > TOKEN_SLOT_WIDTH:
        raise DemoError(f"approval token exceeds slot width {TOKEN_SLOT_WIDTH}")
    return template.replace(TOKEN_SLOT_MARKER, approval_token.ljust(TOKEN_SLOT_WIDTH))


def host_patch_code_template(*, patch_text: str, base_revision: str, ticket_slot: str) -> str:
    token_literal = json.dumps(ticket_slot)
    patch_literal = json.dumps(patch_text)
    base_literal = json.dumps(base_revision)
    return f"""import os
import subprocess
from pathlib import Path

PATCH_TEXT = {patch_literal}
BASE_REVISION = {base_literal}
TOKEN = {token_literal}.rstrip()

patch_path = Path("/tmp/aegis-demo.patch")
patch_path.write_text(PATCH_TEXT, encoding="utf-8")
env = os.environ.copy()
if TOKEN:
    env["AEGIS_APPROVAL_TICKET_TOKEN"] = TOKEN
proc = subprocess.run(
    [
        "/usr/local/bin/guest-runner",
        "host-repo-apply-patch",
        "--repo-label",
        "{DEMO_REPO_LABEL}",
        "--patch-file",
        str(patch_path),
        "--base-revision",
        BASE_REVISION,
    ],
    text=True,
    capture_output=True,
    env=env,
    check=False,
)
if proc.stdout:
    print(proc.stdout, end="")
if proc.stderr:
    print(proc.stderr, end="")
raise SystemExit(proc.returncode)
"""


def render_guest_patch_script(code_path: Path, *, approval_token: str) -> str:
    template = code_path.read_text(encoding="utf-8")
    return inject_approval_token(template, approval_token)


def broker_http_code_template(*, port: int, ticket_slot: str) -> str:
    token_literal = json.dumps(ticket_slot)
    return f"""import socket

TOKEN = {token_literal}.rstrip()
sock = socket.create_connection(("127.0.0.1", 8888), timeout=5)
try:
    headers = [
        "GET http://127.0.0.1:{port}/probe HTTP/1.1",
        "Host: 127.0.0.1:{port}",
        "Connection: close",
        "X-Aegis-Governed-Action: http_request",
    ]
    if TOKEN:
        headers.append("X-Aegis-Approval-Ticket: " + TOKEN)
    request = ("\\r\\n".join(headers) + "\\r\\n\\r\\n").encode()
    sock.sendall(request)
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    text = response.decode("utf-8", errors="replace")
    print(text)
    if "auth_present=true" not in text:
        raise SystemExit(1)
finally:
    sock.close()
"""


def render_guest_broker_http_script(*, port: int, approval_token: str) -> str:
    template = broker_http_code_template(port=port, ticket_slot=approval_token_slot())
    return inject_approval_token(template, approval_token)


def preview_demo_execution(code_path: Path, intent_path: Path, *, language: str) -> dict[str, str]:
    cli = require_file(CLI_BIN, "repo-local aegis CLI binary")
    proc = subprocess_run(
        [str(cli), "demo", "prepare", "--config", str(CONFIG_PATH), "--lang", language, "--file", str(code_path), "--intent-file", str(intent_path), "--timeout", str(DEFAULT_TIMEOUT_MS)],
        cwd=REPO_DIR,
        env=demo_cli_env(),
        label="preview demo admission",
    )
    summary = parse_summary(proc.stdout)
    if summary.get("status") != "prepared":
        raise DemoError(f"demo prepare did not return status=prepared:\n{proc.stdout}")
    return summary


def sanitize_approval_issue_output(output: str) -> str:
    lines = []
    for raw in output.splitlines():
        if raw.startswith("approval_ticket_token="):
            continue
        lines.append(raw)
    return "\n".join(lines).strip() + "\n"


def issue_http_approval(*, execution_id: str, policy_digest: str, method: str, url: str, artifact_dir: Path) -> dict[str, str]:
    cli = require_file(CLI_BIN, "repo-local aegis CLI binary")
    proc = subprocess_run(
        [
            str(cli),
            "approval",
            "issue",
            "http",
            "--execution-id",
            execution_id,
            "--policy-digest",
            policy_digest,
            "--method",
            method,
            "--url",
            url,
            "--ttl",
            DEFAULT_APPROVAL_TTL,
        ],
        cwd=REPO_DIR,
        env=demo_cli_env(),
        label="issue demo http approval",
    )
    sanitized = sanitize_approval_issue_output(proc.stdout)
    (artifact_dir / "approval.summary.txt").write_text(sanitized, encoding="utf-8")
    summary = parse_summary(proc.stdout)
    if summary.get("status") != "issued" or "approval_ticket_token" not in summary:
        raise DemoError(f"http approval issue did not return a token:\n{proc.stdout}")
    return summary


def issue_host_patch_approval(*, execution_id: str, policy_digest: str, repo_label: str, patch_text: str, base_revision: str, artifact_dir: Path) -> dict[str, str]:
    cli = require_file(CLI_BIN, "repo-local aegis CLI binary")
    patch_path = artifact_dir / "patch.diff"
    proc = subprocess_run(
        [
            str(cli),
            "approval",
            "issue",
            "host-repo-apply-patch",
            "--execution-id",
            execution_id,
            "--policy-digest",
            policy_digest,
            "--repo-label",
            repo_label,
            "--patch-file",
            str(patch_path),
            "--base-revision",
            base_revision,
            "--ttl",
            DEFAULT_APPROVAL_TTL,
        ],
        cwd=REPO_DIR,
        env=demo_cli_env(),
        label="issue demo host patch approval",
    )
    sanitized = sanitize_approval_issue_output(proc.stdout)
    (artifact_dir / "approval.summary.txt").write_text(sanitized, encoding="utf-8")
    summary = parse_summary(proc.stdout)
    if summary.get("status") != "issued" or "approval_ticket_token" not in summary:
        raise DemoError(f"host patch approval issue did not return a token:\n{proc.stdout}")
    return summary


def derive_approval_public_keys_json(approval_seed: str) -> str:
    cli = require_file(CLI_BIN, "repo-local aegis CLI binary")
    env = os.environ.copy()
    env["AEGIS_APPROVAL_SIGNING_SEED_B64"] = approval_seed
    proc = subprocess_run(
        [str(cli), "approval", "public-keys"],
        cwd=REPO_DIR,
        env=env,
        label="derive demo approval public keys",
    )
    summary = parse_summary(proc.stdout)
    if summary.get("status") != "derived":
        raise DemoError(f"approval public-keys did not return status=derived:\n{proc.stdout}")
    public_keys_json = summary.get("public_keys_json", "").strip()
    if public_keys_json == "":
        raise DemoError(f"approval public-keys did not return public_keys_json:\n{proc.stdout}")
    return public_keys_json


@dataclass(slots=True)
class DemoResult:
    run_output: str
    user_output: str
    proof_dir: str
    show_output: str
    verify_output: str
    summary: dict[str, str]
    artifact_dir: str
    status: str
    verify_command: str


def run_cli_demo(
    *,
    label: str,
    run_args: list[str],
    expected_run_codes: set[int],
    expected_verify: dict[str, str],
    contains_verify: list[str] | None = None,
    artifact_dir: Path,
    status: str,
) -> DemoResult:
    state = require_state()
    cli = require_file(CLI_BIN, "repo-local aegis CLI binary")
    env = cli_env(state)
    run_proc = subprocess.run(
        [str(cli), *run_args],
        cwd=REPO_DIR,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    combined_output = (run_proc.stdout or "") + (run_proc.stderr or "")
    if run_proc.returncode not in expected_run_codes:
        raise DemoError(f"{label}: unexpected run exit code {run_proc.returncode}; expected {sorted(expected_run_codes)}\n{combined_output}")
    proof_dir = extract_proof_dir(combined_output)
    if proof_dir == "":
        raise DemoError(f"{label}: missing proof bundle path in CLI output:\n{combined_output}")

    show_proc = subprocess.run(
        [str(cli), "receipt", "show", "--proof-dir", proof_dir],
        cwd=REPO_DIR,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if show_proc.returncode != 0:
        raise DemoError(f"{label}: receipt show failed:\n{show_proc.stdout}{show_proc.stderr}")

    verify_proc = subprocess.run(
        [str(cli), "receipt", "verify", "--proof-dir", proof_dir],
        cwd=REPO_DIR,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if verify_proc.returncode != 0:
        raise DemoError(f"{label}: receipt verify failed:\n{verify_proc.stdout}{verify_proc.stderr}")

    verify_output = verify_proc.stdout + verify_proc.stderr
    for key, want in expected_verify.items():
        got = parse_summary(verify_output).get(key, "")
        if got != want:
            raise DemoError(f"{label}: expected {key}={want!r}, got {got!r}\n{verify_output}")
    for needle in contains_verify or []:
        if needle not in verify_output:
            raise DemoError(f"{label}: expected receipt verify output to contain {needle!r}\n{verify_output}")

    user_output = extract_user_output(combined_output)
    (artifact_dir / "run.output.txt").write_text(user_output + ("\n" if user_output else ""), encoding="utf-8")
    (artifact_dir / "receipt.show.txt").write_text(show_proc.stdout + show_proc.stderr, encoding="utf-8")
    (artifact_dir / "receipt.verify.txt").write_text(verify_output, encoding="utf-8")
    verify_command = f"{cli} receipt verify --proof-dir {proof_dir}"

    return DemoResult(
        run_output=combined_output,
        user_output=user_output,
        proof_dir=proof_dir,
        show_output=show_proc.stdout + show_proc.stderr,
        verify_output=verify_output,
        summary=parse_summary(verify_output),
        artifact_dir=str(artifact_dir),
        status=status,
        verify_command=verify_command,
    )


def print_demo_result(label: str, result: DemoResult) -> None:
    execution_id = result.summary.get("execution_id", "unknown")
    print(f"demo={label}")
    print(f"status={result.status}")
    if result.user_output:
        print("stdout:")
        for line in result.user_output.splitlines():
            print(f"  {line}")
    print(f"execution_id={execution_id}")
    print(f"artifact_dir={result.artifact_dir}")
    print(f"proof_dir={result.proof_dir}")
    print(f"verify_command={result.verify_command}")
    print("receipt_summary_key_fields=" + receipt_summary_key_fields(result.summary))
    print(f"verification={result.summary.get('verification', 'unknown')}")


def extract_user_output(run_output: str) -> str:
    lines = []
    for raw in run_output.splitlines():
        line = raw.rstrip()
        if line.startswith("[proof bundle ") or line.startswith("[receipt ") or line.startswith("[done in ") or line.startswith("[receipt public key ") or line.startswith("[receipt summary "):
            continue
        if line == "":
            continue
        lines.append(line)
    return "\n".join(lines)


def ensure_runtime_running() -> None:
    require_preflight()
    if runtime_health(DEFAULT_API_URL):
        return
    raise DemoError("demo runtime is not healthy at http://127.0.0.1:8080; run ./scripts/demo_up.sh first")


def start_demo_runtime() -> DemoState:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    PROOF_ROOT.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_ROOT.mkdir(parents=True, exist_ok=True)
    HOST_REPOS_ROOT.mkdir(parents=True, exist_ok=True)
    db_port = find_free_port()
    postgres_url = f"postgresql://{DEFAULT_DB_USER}@127.0.0.1:{db_port}/{DEFAULT_DB_NAME}?sslmode=disable"

    go_bin = resolve_go_bin()
    firecracker = resolve_firecracker()
    init_local_postgres(db_port)
    apply_schema(db_port)
    run_setup(go_bin, postgres_url)
    require_file(KERNEL_PATH, "kernel image")
    require_file(ROOTFS_PATH, "rootfs image")
    require_file(ORCH_BIN, "repo-local orchestrator binary")
    seed = require_file(REPO_DIR / ".aegis" / "receipt_signing_seed.b64", "receipt signing seed").read_text(encoding="utf-8").strip()
    approval_seed = APPROVAL_SEED_PATH.read_text(encoding="utf-8").strip()
    approval_public_keys_json = derive_approval_public_keys_json(approval_seed)
    lease_seed = LEASE_SEED_PATH.read_text(encoding="utf-8").strip()
    env = os.environ.copy()
    env.update(
        {
            "AEGIS_HTTP_ADDR": DEFAULT_ADDR,
            "AEGIS_FIRECRACKER_BIN": firecracker,
            "AEGIS_ROOTFS_PATH": str(ROOTFS_PATH),
            "AEGIS_PROOF_ROOT": str(PROOF_ROOT),
            "AEGIS_UI_DIR": str(REPO_DIR / "ui"),
            "AEGIS_RECEIPT_SIGNING_MODE": "strict",
            "AEGIS_RECEIPT_SIGNING_SEED_B64": seed,
            "AEGIS_APPROVAL_SIGNING_SEED_B64": approval_seed,
            "AEGIS_APPROVAL_PUBLIC_KEYS_JSON": approval_public_keys_json,
            "AEGIS_LEASE_SIGNING_SEED_B64": lease_seed,
            "AEGIS_HOST_REPOS_JSON": json.dumps({DEMO_REPO_LABEL: str(DEMO_REPO_DIR)}),
            "AEGIS_CRED_DEMO_TOKEN": DEFAULT_BROKER_TOKEN,
        }
    )
    if os.path.isabs(firecracker):
        env["PATH"] = str(Path(firecracker).parent) + os.pathsep + env.get("PATH", "")

    log_handle = RUNTIME_LOG.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [
            str(ORCH_BIN),
            "--db",
            postgres_url,
            "--policy",
            str(POLICY_PATH),
            "--assets-dir",
            str(ASSETS_DIR),
            "--rootfs-path",
            str(ROOTFS_PATH),
            "--addr",
            DEFAULT_ADDR,
        ],
        cwd=REPO_DIR,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    log_handle.close()
    try:
        wait_for_health(DEFAULT_API_URL, timeout_seconds=60)
    except Exception:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        raise

    return DemoState(
        api_url=DEFAULT_API_URL,
        addr=DEFAULT_ADDR,
        runtime_pid=proc.pid,
        runtime_log=str(RUNTIME_LOG),
        postgres_data_dir=str(POSTGRES_DATA),
        postgres_log=str(POSTGRES_LOG),
        postgres_port=db_port,
        postgres_user=DEFAULT_DB_USER,
        postgres_db=DEFAULT_DB_NAME,
        postgres_url=postgres_url,
        proof_root=str(PROOF_ROOT),
        broker_binding="demo",
    )


def cleanup_from_state() -> None:
    state = load_state()
    if state is None:
        return
    stop_runtime(state)
    stop_postgres(state)
    try:
        STATE_PATH.unlink()
    except FileNotFoundError:
        pass


def cleanup_legacy_runtime_inputs() -> None:
    shutil.rmtree(STATE_DIR / "runtime-inputs", ignore_errors=True)


def stop_runtime(state: DemoState) -> None:
    try:
        os.kill(state.runtime_pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        return
    deadline = time.time() + 10
    while time.time() < deadline:
        if not pid_exists(state.runtime_pid):
            return
        time.sleep(0.2)
    try:
        os.kill(state.runtime_pid, signal.SIGKILL)
    except OSError:
        return


def stop_postgres(state: DemoState) -> None:
    pg_ctl = find_postgres_tool("pg_ctl")
    if not Path(state.postgres_data_dir).exists():
        return
    subprocess.run(
        [pg_ctl, "-D", state.postgres_data_dir, "-m", "immediate", "-w", "stop"],
        check=False,
        capture_output=True,
        text=True,
    )


def require_preflight() -> None:
    issues = sorted(collect_preflight_issues())
    if len(issues) == 0:
        return
    rendered = "\n".join(f"- {issue}" for issue in issues)
    raise DemoError(f"demo preflight failed:\n{rendered}")


def collect_preflight_issues() -> list[str]:
    issues: list[str] = []
    if sys.platform != "linux":
        issues.append("Linux host is required")
    else:
        try:
            check_kvm()
        except DemoError as exc:
            issues.append(str(exc))
    for path, label in [
        (CLI_BIN, "repo-local aegis CLI binary"),
        (ORCH_BIN, "repo-local orchestrator binary"),
        (CONFIG_PATH, "demo config yaml"),
        (POLICY_PATH, "default policy"),
        (SCHEMA_PATH, "database schema"),
        (ASSETS_DIR, "assets directory"),
        (KERNEL_PATH, "kernel image"),
        (ROOTFS_PATH, "rootfs image"),
        (REPO_DIR / ".aegis" / "receipt_signing_seed.b64", "receipt signing seed"),
    ]:
        if not path.exists():
            issues.append(f"{label} missing at {path}")
    for checker in [resolve_firecracker, resolve_go_bin]:
        try:
            checker()
        except DemoError as exc:
            issues.append(str(exc))
    for tool in ["initdb", "pg_ctl", "psql"]:
        try:
            find_postgres_tool(tool)
        except DemoError as exc:
            issues.append(str(exc))
    issues.sort()
    return issues


def check_kvm() -> None:
    kvm = Path("/dev/kvm")
    if not kvm.exists():
        raise DemoError("/dev/kvm is missing; enable KVM before running the demo")
    try:
        fd = os.open(kvm, os.O_RDWR)
    except OSError as exc:
        raise DemoError(f"/dev/kvm is not accessible to the current user: {exc}") from exc
    os.close(fd)


def resolve_go_bin() -> str:
    for candidate in [shutil.which("go"), str(Path.home() / "local" / "go" / "bin" / "go")]:
        if candidate and Path(candidate).exists():
            return candidate
    raise DemoError("Go toolchain not found; install go or add it to PATH before running the demo")


def resolve_firecracker() -> str:
    env_value = os.environ.get("AEGIS_FIRECRACKER_BIN", "").strip()
    if env_value:
        candidate = shutil.which(env_value) or env_value
        if Path(candidate).exists():
            return str(Path(candidate))
    candidate = shutil.which("firecracker")
    if candidate:
        return candidate
    raise DemoError("Firecracker binary not found; install firecracker or set AEGIS_FIRECRACKER_BIN")


def find_postgres_tool(name: str) -> str:
    direct = shutil.which(name)
    if direct:
        return direct
    base = Path("/usr/lib/postgresql")
    if base.exists():
        for version_dir in sorted(base.iterdir(), reverse=True):
            candidate = version_dir / "bin" / name
            if candidate.exists():
                return str(candidate)
    raise DemoError(f"Postgres tool {name!r} not found; install PostgreSQL server binaries before running demo_up.sh")


def init_local_postgres(port: int) -> None:
    initdb = find_postgres_tool("initdb")
    pg_ctl = find_postgres_tool("pg_ctl")
    psql = find_postgres_tool("psql")
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    POSTGRES_SOCKET.mkdir(parents=True, exist_ok=True)
    if not (POSTGRES_DATA / "PG_VERSION").exists():
        subprocess_run(
            [initdb, "-D", str(POSTGRES_DATA), "-A", "trust", "-U", DEFAULT_DB_USER, "--no-instructions"],
            label="initdb",
        )
    subprocess.run(
        [pg_ctl, "-D", str(POSTGRES_DATA), "-m", "immediate", "-w", "stop"],
        check=False,
        capture_output=True,
        text=True,
    )
    subprocess_run(
        [
            pg_ctl,
            "-D",
            str(POSTGRES_DATA),
            "-l",
            str(POSTGRES_LOG),
            "-w",
            "start",
            "-o",
            f"-F -h 127.0.0.1 -k {POSTGRES_SOCKET} -p {port}",
        ],
        label="pg_ctl start",
    )
    exists = subprocess.run(
        [psql, "-h", "127.0.0.1", "-p", str(port), "-U", DEFAULT_DB_USER, "-d", "postgres", "-tAc", f"SELECT 1 FROM pg_database WHERE datname = '{DEFAULT_DB_NAME}'"],
        text=True,
        capture_output=True,
        check=False,
    )
    if exists.returncode != 0:
        raise DemoError(f"postgres database probe failed:\n{exists.stdout}{exists.stderr}")
    if exists.stdout.strip() != "1":
        subprocess_run(
            [psql, "-h", "127.0.0.1", "-p", str(port), "-U", DEFAULT_DB_USER, "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", f"CREATE DATABASE {DEFAULT_DB_NAME}"],
            label="create demo database",
        )


def apply_schema(port: int) -> None:
    psql = find_postgres_tool("psql")
    subprocess_run(
        [psql, "-h", "127.0.0.1", "-p", str(port), "-U", DEFAULT_DB_USER, "-d", DEFAULT_DB_NAME, "-v", "ON_ERROR_STOP=1", "-f", str(SCHEMA_PATH)],
        label="apply demo schema",
    )


def run_setup(go_bin: str, postgres_url: str) -> None:
    env = os.environ.copy()
    env["AEGIS_DB_URL"] = postgres_url
    env["AEGIS_URL"] = DEFAULT_API_URL
    env["AEGIS_PROOF_ROOT"] = str(PROOF_ROOT)
    subprocess_run(
        [go_bin, "run", "./cmd/aegis-cli", "setup", "--config", str(CONFIG_PATH)],
        cwd=REPO_DIR,
        env=env,
        label="aegis setup",
    )


def wait_for_health(base_url: str, timeout_seconds: int) -> None:
    deadline = time.time() + timeout_seconds
    last_error = ""
    while time.time() < deadline:
        try:
            req = urllib.request.Request(base_url.rstrip("/") + "/health", method="GET")
            with urllib.request.urlopen(req, timeout=2) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if payload.get("status") == "ok":
                return
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
        time.sleep(1)
    raise DemoError(f"runtime health check did not become ready within {timeout_seconds}s: {last_error}")


def runtime_health(base_url: str) -> bool:
    try:
        req = urllib.request.Request(base_url.rstrip("/") + "/health", method="GET")
        with urllib.request.urlopen(req, timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return payload.get("status") == "ok"
    except Exception:  # noqa: BLE001
        return False


def extract_proof_dir(output: str) -> str:
    for line in output.splitlines():
        match = PROOF_RE.match(line.strip())
        if match:
            return match.group(1)
    return ""


def parse_summary(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key == "":
            continue
        values[key] = value.strip()
    return values


def receipt_summary_key_fields(summary: dict[str, str]) -> str:
    governed = parse_governed_action_fields(summary.get("governed_action_1", ""))
    fields = [
        f"result_class={summary.get('result_class', 'unknown')}",
        f"outcome={summary.get('outcome', 'unknown')}",
        f"authority_digest={summary.get('authority_digest', 'unknown')}",
    ]
    for key in [
        "broker_action_types",
        "broker_repo_labels",
        "lease_result",
        "lease_budget_result",
        "lease_remaining_count",
        "approval_ticket_id",
        "approval_result",
        "approval_reason",
        "host_action_class",
        "repo_label",
        "patch_digest",
        "affected_paths",
        "runtime_policy_escalation_count",
        "runtime_policy_termination_reason",
    ]:
        value = summary.get(key, "").strip() or governed.get(key, "").strip()
        if value:
            fields.append(f"{key}={value}")
    return " ".join(fields)


def parse_governed_action_fields(raw: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for chunk in raw.split():
        if "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def save_state(state: DemoState) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def load_state() -> DemoState | None:
    if not STATE_PATH.exists():
        return None
    raw = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return DemoState.from_dict(raw)


def require_state() -> DemoState:
    state = load_state()
    if state is None:
        raise DemoError("demo runtime state not found; run ./scripts/demo_up.sh first")
    return state


def demo_cli_env() -> dict[str, str]:
    env = os.environ.copy()
    approval_seed = ensure_demo_seed(APPROVAL_SEED_PATH)
    env["AEGIS_APPROVAL_SIGNING_SEED_B64"] = approval_seed
    env["AEGIS_APPROVAL_PUBLIC_KEYS_JSON"] = derive_approval_public_keys_json(approval_seed)
    env["AEGIS_LEASE_SIGNING_SEED_B64"] = ensure_demo_seed(LEASE_SEED_PATH)
    return env


def cli_env(state: DemoState) -> dict[str, str]:
    env = demo_cli_env()
    env["AEGIS_URL"] = state.api_url
    env["AEGIS_PROOF_ROOT"] = state.proof_root
    return env


def subprocess_run(cmd: list[str], *, label: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise DemoError(f"{label} failed:\ncommand={' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
    return proc


def require_file(path: Path, label: str) -> Path:
    if not path.exists():
        raise DemoError(f"{label} missing at {path}")
    return path


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return int(sock.getsockname()[1])


def pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def print_next_steps() -> None:
    print("next=python3 ./scripts/aegis_demo.py preflight")
    print("next=./scripts/demo_escalation_termination.sh")
    print("next=./scripts/demo_host_patch_denied.sh")
    print("next=./scripts/demo_host_patch_approved.sh")
    print("next=./scripts/demo_broker_http.sh")
    print("next=python3 ./scripts/aegis_demo.py canonical-suite")
    print("next=./scripts/demo_status.sh")
    print("next=./scripts/demo_down.sh")


if __name__ == "__main__":
    raise SystemExit(main())
