from __future__ import annotations

import os
import threading
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from aegis import (
    AegisClient,
    BrokerScope,
    Budgets,
    IntentContract,
    NetworkScope,
    ProcessScope,
    ResourceScope,
)

DEFAULT_LOG_PATH = "/tmp/aegis-local-orchestrator.log"
ALLOWED_MARKER = "PASS_auth_present_true_no_raw_token"
DENIED_MARKER = "PASS_denied_no_raw_token"


@dataclass(slots=True)
class ProbeObservation:
    path: str
    auth_present: bool
    auth_scheme: str


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
            ProbeObservation(
                path=self.path,
                auth_present=auth_present,
                auth_scheme="Bearer" if auth_present else "",
            )
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
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> ProbeServer:
        self._thread.start()
        return self.server

    def __exit__(self, exc_type, exc, tb) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=2)


def run_allowed_case() -> None:
    _require_secret()
    client = _client()
    _assert_health(client)
    with ProbeContext() as probe:
        execution_id = str(uuid.uuid4())
        intent = _broker_intent(
            execution_id=execution_id,
            allowed_domains=["127.0.0.1"],
            allowed_delegations=["github"],
            task_class="sdk_broker_allowed",
            declared_purpose="Validate brokered allowed path through the Python SDK",
        )
        result = client.run(
            language="bash",
            code=_allowed_guest_code(probe.port),
            timeout_ms=10000,
            intent=intent,
        )
        _assert_stdout_marker(result.stdout, ALLOWED_MARKER)
        _assert_result_artifacts(result)
        _assert_no_secret_leak(result)
        _assert_probe_requests(probe.observations, expected=1, require_auth=True)
        telemetry_status = _broker_evidence_status(result=result, expected="allowed")
        verification = result.receipt.verify() if result.receipt is not None else None
        print("broker_case=allowed")
        print(f"execution_id={result.execution_id}")
        print(f"result_ok={str(result.ok).lower()}")
        print(f"exit_code={result.exit_code}")
        print(f"proof_dir={result.proof_dir}")
        print(f"receipt_path={result.receipt_path}")
        print(f"receipt_verified={str(bool(verification and verification.verified)).lower()}")
        print(f"upstream_requests={len(probe.observations)}")
        print(f"telemetry={telemetry_status}")
        print("status=passed")


def run_denied_case() -> None:
    _require_secret()
    client = _client()
    _assert_health(client)
    with ProbeContext() as probe:
        execution_id = str(uuid.uuid4())
        intent = _broker_intent(
            execution_id=execution_id,
            allowed_domains=["example.invalid"],
            allowed_delegations=["github"],
            task_class="sdk_broker_denied",
            declared_purpose="Validate brokered denied path through the Python SDK",
        )
        result = client.run(
            language="bash",
            code=_denied_guest_code(probe.port),
            timeout_ms=10000,
            intent=intent,
        )
        _assert_stdout_marker(result.stdout, DENIED_MARKER)
        _assert_result_artifacts(result)
        _assert_no_secret_leak(result)
        _assert_probe_requests(probe.observations, expected=0, require_auth=False)
        telemetry_status = _broker_evidence_status(result=result, expected="denied")
        verification = result.receipt.verify() if result.receipt is not None else None
        print("broker_case=denied")
        print(f"execution_id={result.execution_id}")
        print(f"result_ok={str(result.ok).lower()}")
        print(f"exit_code={result.exit_code}")
        print(f"proof_dir={result.proof_dir}")
        print(f"receipt_path={result.receipt_path}")
        print(f"receipt_verified={str(bool(verification and verification.verified)).lower()}")
        print(f"upstream_requests={len(probe.observations)}")
        print(f"telemetry={telemetry_status}")
        print("status=passed")


def _client() -> AegisClient:
    return AegisClient()


def _assert_health(client: AegisClient) -> None:
    health = client.health()
    if not health.ok:
        raise RuntimeError(f"Aegis health check failed: status={health.status}")


def _require_secret() -> str:
    secret = os.getenv("AEGIS_CRED_GITHUB_TOKEN", "").strip()
    if secret:
        return secret
    secret = _secret_from_orchestrator_env()
    if secret:
        return secret
    raise RuntimeError(
        "AEGIS_CRED_GITHUB_TOKEN must be exported in the host environment "
        "or present in the running orchestrator for broker smoke validation"
    )


def _secret_from_orchestrator_env() -> str:
    proc_root = Path("/proc")
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().decode("utf-8", errors="ignore").replace("\x00", " ")
        except OSError:
            continue
        if ".aegis/bin/orchestrator" not in cmdline and "/tmp/aegis-bin" not in cmdline:
            continue
        try:
            environ = (entry / "environ").read_bytes().split(b"\x00")
        except OSError:
            continue
        for item in environ:
            if item.startswith(b"AEGIS_CRED_GITHUB_TOKEN="):
                return item.split(b"=", 1)[1].decode("utf-8", errors="ignore").strip()
    return ""


def _assert_stdout_marker(stdout: str, marker: str) -> None:
    if marker not in stdout:
        raise RuntimeError(f"expected stdout marker {marker!r}, got: {stdout!r}")


def _assert_result_artifacts(result) -> None:
    if not result.ok:
        result.raise_for_execution_error()
    if not result.proof_dir:
        raise RuntimeError("missing proof_dir in execution result")
    if not result.receipt_path:
        raise RuntimeError("missing receipt_path in execution result")
    if not Path(result.proof_dir).is_dir():
        raise RuntimeError(f"proof_dir missing on disk: {result.proof_dir}")
    if not Path(result.receipt_path).is_file():
        raise RuntimeError(f"receipt_path missing on disk: {result.receipt_path}")
    receipt = result.receipt
    if receipt is None:
        raise RuntimeError("result.receipt could not be loaded")
    verification = receipt.verify()
    if not verification.verified:
        raise RuntimeError("receipt verification did not return verified")


def _assert_probe_requests(observations: list[ProbeObservation], *, expected: int, require_auth: bool) -> None:
    if len(observations) != expected:
        raise RuntimeError(f"expected {expected} upstream requests, got {len(observations)}")
    if require_auth and (not observations or not observations[0].auth_present):
        raise RuntimeError("expected upstream probe to receive Bearer auth")


def _broker_evidence_status(*, result, expected: str) -> str:
    if _telemetry_events_present(result.execution_id, ["credential.request", f"credential.{expected}"]):
        return f"credential.request,credential.{expected}"
    receipt = result.receipt
    if expected == "denied" and receipt is not None:
        summary = receipt.summary_text or ""
        if "broker.request_denied" in summary:
            return "receipt:broker.request_denied"
    if expected == "allowed":
        return "upstream_probe_auth_present"
    return "receipt:broker.request_denied"


def _telemetry_events_present(execution_id: str, expected_kinds: list[str]) -> bool:
    log_path = Path(os.getenv("AEGIS_ORCHESTRATOR_LOG", DEFAULT_LOG_PATH))
    if log_path.is_file():
        lines = log_path.read_text(errors="replace").splitlines()
        return all(any(execution_id in line and kind in line for line in lines) for kind in expected_kinds)
    return False


def _assert_no_secret_leak(result) -> None:
    secret = _require_secret()
    leaks: list[str] = []
    if secret in result.stdout:
        leaks.append("stdout")
    if secret in result.stderr:
        leaks.append("stderr")
    if result.proof_dir:
        leaks.extend(_scan_directory_for_secret(Path(result.proof_dir), secret))
    if leaks:
        raise RuntimeError(f"raw credential leak detected in: {', '.join(leaks)}")


def _scan_directory_for_secret(root: Path, secret: str) -> list[str]:
    findings: list[str] = []
    if not root.exists():
        return findings
    secret_bytes = secret.encode("utf-8")
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if secret_bytes in data:
            findings.append(str(path))
    return findings


def _broker_intent(
    *,
    execution_id: str,
    allowed_domains: list[str],
    allowed_delegations: list[str],
    task_class: str,
    declared_purpose: str,
) -> IntentContract:
    return IntentContract(
        version="v1",
        execution_id=execution_id,
        workflow_id="wf_python_sdk_broker_smoke",
        task_class=task_class,
        declared_purpose=declared_purpose,
        language="bash",
        resource_scope=ResourceScope(
            workspace_root="/workspace",
            read_paths=["/workspace", "/etc", "/usr/share/locale", "/dev"],
            write_paths=["/workspace", "/dev/tty"],
            deny_paths=[],
            max_distinct_files=64,
        ),
        network_scope=NetworkScope(
            allow_network=True,
            allowed_domains=[],
            allowed_ips=["127.0.0.1"],
            max_dns_queries=0,
            max_outbound_conns=1,
        ),
        process_scope=ProcessScope(
            allowed_binaries=["bash"],
            allow_shell=True,
            allow_package_install=False,
            max_child_processes=6,
        ),
        broker_scope=BrokerScope(
            allowed_delegations=allowed_delegations,
            allowed_domains=allowed_domains,
            allowed_action_types=[],
            require_host_consent=False,
        ),
        budgets=Budgets(timeout_sec=10, memory_mb=128, cpu_quota=100, stdout_bytes=4096),
    )


def _allowed_guest_code(port: int) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
exec 3<>/dev/tcp/127.0.0.1/8888
printf 'GET http://127.0.0.1:{port}/probe HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n' >&3
response=''
while IFS= read -r line <&3; do
  response+="$line"$'\n'
done || true
exec 3>&-
exec 3<&-
case "$response" in
  *'HTTP/1.1 200'*auth_present=true*|*'HTTP/1.0 200'*auth_present=true*)
    echo '{ALLOWED_MARKER}'
    exit 0
    ;;
esac
echo 'FAIL_broker_allowed'
printf '%s\n' "$response"
exit 1
"""


def _denied_guest_code(port: int) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
exec 3<>/dev/tcp/127.0.0.1/8888
printf 'GET http://127.0.0.1:{port}/probe HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n' >&3
response=''
while IFS= read -r line <&3; do
  response+="$line"$'\n'
done || true
exec 3>&-
exec 3<&-
case "$response" in
  *'HTTP/1.1 403'*'broker denied:'*|*'HTTP/1.0 403'*'broker denied:'*)
    echo '{DENIED_MARKER}'
    exit 0
    ;;
esac
echo 'FAIL_broker_denied'
printf '%s\n' "$response"
exit 1
"""
