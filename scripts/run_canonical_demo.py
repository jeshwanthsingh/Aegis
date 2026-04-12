#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
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
DEFAULT_CONFIG_PATH = REPO_DIR / ".aegis" / "config.yaml"
DEFAULT_CLI_BIN = REPO_DIR / ".aegis" / "bin" / "aegis"
DEFAULT_BASE_URL = "http://localhost:8080"
DEFAULT_RUNTIME_LOG = "/tmp/aegis-canonical-demo-runtime.log"
DEFAULT_WARM_POOL_SIZE = 1
DEFAULT_BROKER_TOKEN = "aegis-demo-token"
DEFAULT_TIMEOUT_MS = 10000
ALLOWED_MARKER = "PASS_auth_present_true_no_raw_token"
DENIED_MARKER = "PASS_direct_network_denied"
POSTGRES_BIN_DIR = Path("/usr/lib/postgresql/16/bin")
POSTGRES_INITDB = POSTGRES_BIN_DIR / "initdb"
POSTGRES_PG_CTL = POSTGRES_BIN_DIR / "pg_ctl"
POSTGRES_PSQL = POSTGRES_BIN_DIR / "psql"
POSTGRES_USER = "aegisdemo"


@dataclass(slots=True)
class ExecutionResult:
    label: str
    response: dict
    verify_output: str

    @property
    def proof_dir(self) -> str:
        value = self.response.get("proof_dir")
        if not isinstance(value, str) or not value:
            raise RuntimeError(f"{self.label}: missing proof_dir in response: {self.response}")
        return value

    @property
    def execution_id(self) -> str:
        value = self.response.get("execution_id")
        if not isinstance(value, str) or not value:
            raise RuntimeError(f"{self.label}: missing execution_id in response: {self.response}")
        return value

    @property
    def duration_ms(self) -> int:
        return int(self.response.get("duration_ms", 0))

    @property
    def dispatch_path(self) -> str:
        value = self.response.get("dispatch_path", "")
        return value if isinstance(value, str) else ""


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


class LocalPostgres:
    def __init__(self, schema_path: Path) -> None:
        self.schema_path = schema_path
        self.root = Path(tempfile.mkdtemp(prefix="aegis-demo-pg-"))
        self.data_dir = self.root / "data"
        self.log_path = self.root / "postgres.log"
        self.socket_dir = self.root / "socket"
        self.port = find_free_port()
        self.db_url = f"postgresql://{POSTGRES_USER}@127.0.0.1:{self.port}/aegis?sslmode=disable"

    def __enter__(self) -> "LocalPostgres":
        require_file(POSTGRES_INITDB, "postgres initdb binary")
        require_file(POSTGRES_PG_CTL, "postgres pg_ctl binary")
        require_file(POSTGRES_PSQL, "postgres psql binary")
        self.socket_dir.mkdir(parents=True, exist_ok=True)
        subprocess_run(
            [
                str(POSTGRES_INITDB),
                "-D",
                str(self.data_dir),
                "-A",
                "trust",
                "-U",
                POSTGRES_USER,
                "--no-instructions",
            ],
            label="initdb",
        )
        subprocess_run(
            [
                str(POSTGRES_PG_CTL),
                "-D",
                str(self.data_dir),
                "-l",
                str(self.log_path),
                "-w",
                "start",
                "-o",
                f"-F -h 127.0.0.1 -k {self.socket_dir} -p {self.port}",
            ],
            label="pg_ctl start",
        )
        subprocess_run(
            [
                str(POSTGRES_PSQL),
                "-h",
                "127.0.0.1",
                "-p",
                str(self.port),
                "-U",
                POSTGRES_USER,
                "-d",
                "postgres",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                "CREATE DATABASE aegis",
            ],
            label="create demo database",
        )
        subprocess_run(
            [
                str(POSTGRES_PSQL),
                "-h",
                "127.0.0.1",
                "-p",
                str(self.port),
                "-U",
                POSTGRES_USER,
                "-d",
                "aegis",
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                str(self.schema_path),
            ],
            label="apply demo schema",
        )
        print(f"demo_db_url={self.db_url}")
        print(f"demo_db_log={self.log_path}")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        subprocess.run(
            [
                str(POSTGRES_PG_CTL),
                "-D",
                str(self.data_dir),
                "-m",
                "immediate",
                "-w",
                "stop",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        shutil.rmtree(self.root, ignore_errors=True)


class LocalRuntime:
    def __init__(
        self,
        *,
        go_bin: Path,
        cli_bin: Path,
        config_path: Path,
        base_url: str,
        db_url: str,
        runtime_log: Path,
        warm_pool_size: int,
        broker_token: str,
    ) -> None:
        self.go_bin = go_bin
        self.cli_bin = cli_bin
        self.config_path = config_path
        self.base_url = base_url.rstrip("/")
        self.db_url = db_url
        self.runtime_log = runtime_log
        self.warm_pool_size = warm_pool_size
        self.broker_token = broker_token
        self.proc: subprocess.Popen[str] | None = None
        self._log_handle = None

    def __enter__(self) -> "LocalRuntime":
        require_file(self.go_bin, "go toolchain")
        require_file(self.cli_bin, "aegis CLI binary")
        require_file(self.config_path, "repo-local Aegis config")
        env = os.environ.copy()
        env["AEGIS_CONFIG"] = str(self.config_path)
        env["AEGIS_DB_URL"] = self.db_url
        env["AEGIS_WARM_POOL_SIZE"] = str(self.warm_pool_size)
        env["AEGIS_CRED_GITHUB_TOKEN"] = self.broker_token
        env.setdefault("AEGIS_URL", self.base_url)
        subprocess_run(
            [str(self.go_bin), "run", "./cmd/aegis-cli", "setup", "--config", str(self.config_path)],
            label="refresh repo-local Aegis binaries",
            cwd=REPO_DIR,
            env=env,
        )
        self.runtime_log.parent.mkdir(parents=True, exist_ok=True)
        self._log_handle = self.runtime_log.open("w", encoding="utf-8")
        self.proc = subprocess.Popen(
            [str(self.cli_bin), "serve", "--config", str(self.config_path)],
            cwd=REPO_DIR,
            env=env,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        wait_for_health(self.base_url, timeout_seconds=60)
        print(f"runtime_mode=started_local")
        print(f"runtime_log={self.runtime_log}")
        print(f"runtime_config={self.config_path}")
        print(f"runtime_db_override={self.db_url}")
        print(f"runtime_warm_pool_size_override={self.warm_pool_size}")
        print("runtime_broker_token_source=synthetic_local_demo_token")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        if self._log_handle is not None:
            self._log_handle.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the canonical Aegis demo / red-team harness.")
    parser.add_argument("--serve", action="store_true", help="Start a local repo-configured runtime when one is not already healthy.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to the repo-local Aegis config.")
    parser.add_argument("--base-url", default=os.environ.get("BASE_URL", DEFAULT_BASE_URL), help="Aegis API base URL.")
    parser.add_argument("--runtime-log", default=DEFAULT_RUNTIME_LOG, help="Log file for a runtime started by this script.")
    parser.add_argument("--warm-pool-size", type=int, default=DEFAULT_WARM_POOL_SIZE, help="Warm pool size override used only in --serve mode.")
    parser.add_argument("--broker-token", default=DEFAULT_BROKER_TOKEN, help="Synthetic broker token used only in --serve mode for the loopback probe.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_url = args.base_url.rstrip("/")
    config_path = Path(args.config).resolve()
    runtime_log = Path(args.runtime_log).resolve()
    go_bin = resolve_go_bin()
    cli_bin = resolve_cli_bin()
    verify_cmd = [str(cli_bin), "receipt", "verify"]
    print(f"canonical_demo_base_url={base_url}")
    print(f"canonical_demo_config={config_path}")
    print(f"canonical_demo_cli={cli_bin}")
    print(f"verify_cmd={' '.join(verify_cmd)}")

    runtime_started_here = False
    postgres_ctx: LocalPostgres | None = None
    runtime_ctx: LocalRuntime | None = None

    try:
        if runtime_health(base_url) is not None:
            print("runtime_mode=reused_existing")
        else:
            if not args.serve:
                raise RuntimeError(
                    "runtime unavailable. Reuse a healthy runtime or run "
                    f"`{REPO_DIR / 'scripts' / 'run_canonical_demo.py'} --serve` "
                    f"or `{cli_bin} serve --config {config_path}`"
                )
            postgres_ctx = LocalPostgres(REPO_DIR / "db" / "schema.sql")
            postgres_ctx.__enter__()
            runtime_ctx = LocalRuntime(
                go_bin=go_bin,
                cli_bin=cli_bin,
                config_path=config_path,
                base_url=base_url,
                db_url=postgres_ctx.db_url,
                runtime_log=runtime_log,
                warm_pool_size=args.warm_pool_size,
                broker_token=args.broker_token,
            )
            runtime_ctx.__enter__()
            runtime_started_here = True

        warm = run_cold_vs_warm(base_url, verify_cmd)
        allowed = warm["cold"]
        denied = run_governed_deny(base_url, verify_cmd)
        workspace = run_workspace_flow(base_url, verify_cmd)

        print("status=passed")
        print("sections=governed_action,workspace_continuity,cold_vs_warm")
        print(f"allowed_execution_id={allowed.execution_id}")
        print(f"denied_execution_id={denied.execution_id}")
        print(f"workspace_write_execution_id={workspace['write'].execution_id}")
        print(f"workspace_read_execution_id={workspace['read'].execution_id}")
        print(f"cold_execution_id={warm['cold'].execution_id}")
        print(f"warm_execution_id={warm['warm'].execution_id}")
        print(f"runtime_started_here={str(runtime_started_here).lower()}")
        return 0
    finally:
        if runtime_ctx is not None:
            runtime_ctx.__exit__(None, None, None)
        if postgres_ctx is not None:
            postgres_ctx.__exit__(None, None, None)


def resolve_cli_bin() -> Path:
    if DEFAULT_CLI_BIN.is_file():
        return DEFAULT_CLI_BIN
    found = shutil.which("aegis")
    if found:
        return Path(found)
    raise RuntimeError(f"missing Aegis CLI binary at {DEFAULT_CLI_BIN}; run `aegis setup` first")


def resolve_go_bin() -> Path:
    found = shutil.which("go")
    if found:
        return Path(found)
    raise RuntimeError("missing `go` on PATH; required to refresh repo-local Aegis binaries before local serve")


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise RuntimeError(f"{label} missing at {path}")


def subprocess_run(command: list[str], *, label: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, text=True, capture_output=True, check=False, cwd=cwd, env=env)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"{label} failed: {' '.join(command)}\n{detail}")
    return completed


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return int(sock.getsockname()[1])


def headers() -> dict[str, str]:
    hdrs = {"Content-Type": "application/json"}
    token = os.environ.get("AEGIS_API_KEY", "").strip()
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    return hdrs


def http_json(base_url: str, method: str, path: str, payload: dict | None = None, *, expected_status: int | None = None) -> tuple[int, dict]:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
    request = urllib.request.Request(base_url.rstrip("/") + path, data=data, method=method, headers=headers())
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.getcode()
            body = response.read().decode()
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read().decode()
    parsed = json.loads(body) if body else {}
    if expected_status is not None and status != expected_status:
        raise RuntimeError(f"{method} {path} returned {status}, want {expected_status}: {parsed}")
    return status, parsed


def runtime_health(base_url: str) -> dict | None:
    try:
        _, payload = http_json(base_url, "GET", "/health", expected_status=200)
    except (OSError, urllib.error.URLError, RuntimeError):
        return None
    return payload


def wait_for_health(base_url: str, *, timeout_seconds: float) -> dict:
    deadline = time.time() + timeout_seconds
    last_error = "health check did not succeed"
    while time.time() < deadline:
        try:
            _, payload = http_json(base_url, "GET", "/health", expected_status=200)
            if payload.get("status") == "ok":
                return payload
            last_error = f"unexpected health payload: {payload}"
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
        time.sleep(0.25)
    raise RuntimeError(f"runtime failed health check at {base_url}: {last_error}")


def execute(base_url: str, label: str, payload: dict, verify_cmd: list[str], *, expect_exit_code: int | None = None, expect_error: str | None = None) -> ExecutionResult:
    _, response = http_json(base_url, "POST", "/v1/execute", payload, expected_status=200)
    error = response.get("error", "")
    if expect_error is not None:
        if error != expect_error:
            raise RuntimeError(f"{label}: error={error!r}, want {expect_error!r}; response={response}")
        return ExecutionResult(label=label, response=response, verify_output="")
    if error:
        raise RuntimeError(f"{label}: unexpected API error: {response}")
    actual_exit_code = int(response.get("exit_code", 0))
    if expect_exit_code is not None and actual_exit_code != expect_exit_code:
        raise RuntimeError(f"{label}: exit_code={actual_exit_code}, want {expect_exit_code}; response={response}")
    verify_output = verify_proof(verify_cmd, response)
    return ExecutionResult(label=label, response=response, verify_output=verify_output)


def verify_proof(verify_cmd: list[str], response: dict) -> str:
    proof_dir = response.get("proof_dir")
    if not isinstance(proof_dir, str) or not proof_dir:
        raise RuntimeError(f"missing proof_dir for verification: {response}")
    completed = subprocess.run(
        [*verify_cmd, "--proof-dir", proof_dir],
        cwd=REPO_DIR,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"receipt verify failed for {proof_dir}: {completed.stderr or completed.stdout}")
    return completed.stdout


def require_contains(haystack: str, needle: str, *, label: str) -> None:
    if needle not in haystack:
        raise RuntimeError(f"{label}: expected to find {needle!r} in:\n{haystack}")


def print_case(label: str, result: ExecutionResult) -> None:
    print(f"[{label}] execution_id={result.execution_id}")
    print(f"[{label}] dispatch_path={result.dispatch_path or 'n/a'} duration_ms={result.duration_ms}")
    print(f"[{label}] proof_dir={result.proof_dir}")
    print(result.verify_output.rstrip())


def base_intent(*, execution_id: str, language: str, allow_network: bool, allowed_ips: list[str], allowed_domains: list[str], allowed_binaries: list[str], allow_shell: bool, allowed_delegations: list[str], broker_domains: list[str], task_class: str, declared_purpose: str) -> dict:
    return {
        "version": "v1",
        "execution_id": execution_id,
        "workflow_id": "wf_canonical_demo_v1",
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


def governed_allow_payload(port: int, execution_id: str) -> dict:
    code = f"""#!/usr/bin/env bash
set -euo pipefail
exec 3<>/dev/tcp/127.0.0.1/8888
printf 'GET http://127.0.0.1:{port}/probe HTTP/1.1\\r\\nHost: 127.0.0.1:{port}\\r\\nConnection: close\\r\\n\\r\\n' >&3
response=''
while IFS= read -r line <&3; do
  response+="$line"$'\\n'
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
printf '%s\\n' "$response"
exit 1
"""
    return {
        "lang": "bash",
        "code": code,
        "timeout_ms": DEFAULT_TIMEOUT_MS,
        "profile": "standard",
        "intent": base_intent(
            execution_id=execution_id,
            language="bash",
            allow_network=True,
            allowed_ips=["127.0.0.1"],
            allowed_domains=[],
            allowed_binaries=["bash"],
            allow_shell=True,
            allowed_delegations=["github"],
            broker_domains=["127.0.0.1"],
            task_class="canonical_governed_allow",
            declared_purpose="Prove brokered http_request allow path with receipt evidence",
        ),
    }


def governed_deny_payload(execution_id: str) -> dict:
    code = f"""import os, socket
s = socket.socket()
s.settimeout(2)
try:
    rc = s.connect_ex(("1.2.3.4", 4444))
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
    print("{DENIED_MARKER}")
raise SystemExit(exit_code)
"""
    return {
        "lang": "python",
        "code": code,
        "timeout_ms": DEFAULT_TIMEOUT_MS,
        "profile": "standard",
        "intent": base_intent(
            execution_id=execution_id,
            language="python",
            allow_network=False,
            allowed_ips=[],
            allowed_domains=[],
            allowed_binaries=["python3"],
            allow_shell=False,
            allowed_delegations=[],
            broker_domains=[],
            task_class="canonical_governed_deny",
            declared_purpose="Prove denied direct network connect with receipt evidence",
        ),
    }


def workspace_payload(execution_id: str, workspace_id: str, code: str, *, task_class: str, purpose: str) -> dict:
    return {
        "lang": "python",
        "code": code,
        "timeout_ms": DEFAULT_TIMEOUT_MS,
        "workspace_id": workspace_id,
        "intent": base_intent(
            execution_id=execution_id,
            language="python",
            allow_network=False,
            allowed_ips=[],
            allowed_domains=[],
            allowed_binaries=["python3"],
            allow_shell=False,
            allowed_delegations=[],
            broker_domains=[],
            task_class=task_class,
            declared_purpose=purpose,
        ),
    }


def run_governed_allow(base_url: str, verify_cmd: list[str]) -> ExecutionResult:
    with ProbeContext() as probe:
        execution_id = str(uuid.uuid4())
        result = execute(base_url, "governed_allow", governed_allow_payload(probe.port, execution_id), verify_cmd, expect_exit_code=0)
        stdout = str(result.response.get("stdout", ""))
        require_contains(stdout, ALLOWED_MARKER, label="governed_allow stdout")
        if len(probe.observations) != 1 or not probe.observations[0].auth_present:
            raise RuntimeError(f"governed_allow: expected one authenticated upstream probe, got {probe.observations}")
        require_contains(result.verify_output, "verification=verified", label="governed_allow verify")
        require_contains(result.verify_output, "broker_events=credential.request,credential.allowed", label="governed_allow verify")
        require_contains(result.verify_output, "broker_allowed_count=1", label="governed_allow verify")
        require_contains(result.verify_output, "governed_action_1=kind=http_request", label="governed_allow verify")
        require_contains(result.verify_output, "decision=allow", label="governed_allow verify")
        print_case("governed_allow", result)
        return result


def run_governed_deny(base_url: str, verify_cmd: list[str]) -> ExecutionResult:
    execution_id = str(uuid.uuid4())
    result = execute(base_url, "governed_deny", governed_deny_payload(execution_id), verify_cmd)
    stdout = str(result.response.get("stdout", ""))
    require_contains(stdout, DENIED_MARKER, label="governed_deny stdout")
    exit_reason = str(result.response.get("exit_reason", ""))
    if exit_reason not in {"completed", "divergence_terminated"}:
        raise RuntimeError(f"governed_deny: unexpected exit_reason={exit_reason!r}; response={result.response}")
    require_contains(result.verify_output, "verification=verified", label="governed_deny verify")
    require_contains(result.verify_output, "governed_action_1=kind=network_connect", label="governed_deny verify")
    require_contains(result.verify_output, "decision=deny", label="governed_deny verify")
    require_contains(result.verify_output, "denial_marker=direct_egress_denied", label="governed_deny verify")
    print_case("governed_deny", result)
    return result


def run_workspace_flow(base_url: str, verify_cmd: list[str]) -> dict[str, ExecutionResult]:
    workspace_id = f"demo-{uuid.uuid4().hex[:12]}"
    _, created = http_json(base_url, "POST", f"/v1/workspaces/{workspace_id}", expected_status=201)
    if created.get("status") != "created":
        raise RuntimeError(f"workspace create failed: {created}")
    print(f"[workspace] created={workspace_id}")

    write_code = """from pathlib import Path
target = Path("/workspace/demo.txt")
target.write_text("workspace continuity v1\\n")
print(target.read_text().strip())
"""
    read_code = """from pathlib import Path
target = Path("/workspace/demo.txt")
print(target.read_text().strip())
"""

    write = execute(
        base_url,
        "workspace_write",
        workspace_payload(str(uuid.uuid4()), workspace_id, write_code, task_class="canonical_workspace_write", purpose="Write a file into a persistent workspace"),
        verify_cmd,
        expect_exit_code=0,
    )
    require_contains(str(write.response.get("stdout", "")), "workspace continuity v1", label="workspace_write stdout")
    require_contains(write.verify_output, "verification=verified", label="workspace_write verify")
    require_contains(write.verify_output, f"workspace_id={workspace_id}", label="workspace_write verify")
    print_case("workspace_write", write)

    read = execute(
        base_url,
        "workspace_read",
        workspace_payload(str(uuid.uuid4()), workspace_id, read_code, task_class="canonical_workspace_read", purpose="Read a file from a persistent workspace"),
        verify_cmd,
        expect_exit_code=0,
    )
    require_contains(str(read.response.get("stdout", "")), "workspace continuity v1", label="workspace_read stdout")
    require_contains(read.verify_output, "verification=verified", label="workspace_read verify")
    require_contains(read.verify_output, f"workspace_id={workspace_id}", label="workspace_read verify")
    print_case("workspace_read", read)

    _, deleted = http_json(base_url, "DELETE", f"/v1/workspaces/{workspace_id}", expected_status=200)
    if deleted.get("status") != "deleted":
        raise RuntimeError(f"workspace delete failed: {deleted}")
    print(f"[workspace] deleted={workspace_id}")

    missing = execute(
        base_url,
        "workspace_post_delete",
        workspace_payload(str(uuid.uuid4()), workspace_id, read_code, task_class="canonical_workspace_post_delete", purpose="Confirm deleted workspaces fail honestly"),
        verify_cmd,
        expect_error=f"workspace_not_found: {workspace_id}",
    )
    print(f"[workspace_post_delete] execution_id={missing.execution_id}")
    print(f"[workspace_post_delete] error={missing.response.get('error')}")

    post_delete_write_verify = verify_proof(verify_cmd, write.response)
    post_delete_read_verify = verify_proof(verify_cmd, read.response)
    require_contains(post_delete_write_verify, "verification=verified", label="workspace_write post-delete verify")
    require_contains(post_delete_read_verify, "verification=verified", label="workspace_read post-delete verify")
    print(post_delete_write_verify.rstrip())
    print(post_delete_read_verify.rstrip())

    return {"write": write, "read": read}


def warm_pool_status(base_url: str) -> dict:
    health = runtime_health(base_url)
    if health is None:
        raise RuntimeError(f"runtime unavailable at {base_url}")
    warm = health.get("warm_pool") or {}
    if not isinstance(warm, dict):
        raise RuntimeError(f"unexpected warm_pool payload: {warm!r}")
    return warm


def wait_for_warm_available(base_url: str, timeout_seconds: float) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        warm = warm_pool_status(base_url)
        if bool(warm.get("enabled")) and int(warm.get("available", 0)) > 0:
            return True
        time.sleep(0.5)
    return False


def run_cold_vs_warm(base_url: str, verify_cmd: list[str]) -> dict[str, ExecutionResult]:
    warm_before = warm_pool_status(base_url)
    if not bool(warm_before.get("enabled")):
        raise RuntimeError(f"warm pool is not enabled; cannot prove cold vs warm honestly: {warm_before}")

    observed: list[ExecutionResult] = []
    for attempt in range(1, 7):
        with ProbeContext() as probe:
            result = execute(
                base_url,
                f"warm_probe_{attempt}",
                governed_allow_payload(probe.port, str(uuid.uuid4())),
                verify_cmd,
                expect_exit_code=0,
            )
            stdout = str(result.response.get("stdout", ""))
            require_contains(stdout, ALLOWED_MARKER, label=f"warm_probe_{attempt} stdout")
            if len(probe.observations) != 1 or not probe.observations[0].auth_present:
                raise RuntimeError(f"warm_probe_{attempt}: expected one authenticated upstream probe, got {probe.observations}")
            require_contains(result.verify_output, "verification=verified", label=f"warm_probe_{attempt} verify")
            require_contains(result.verify_output, "broker_events=credential.request,credential.allowed", label=f"warm_probe_{attempt} verify")
            require_contains(result.verify_output, "decision=allow", label=f"warm_probe_{attempt} verify")
            observed.append(result)
            print_case(f"warm_probe_{attempt}", result)

        have_cold = next((item for item in observed if item.dispatch_path == "cold"), None)
        have_warm = next((item for item in observed if item.dispatch_path == "warm"), None)
        if have_cold is not None and have_warm is not None:
            speedup = have_cold.duration_ms / max(have_warm.duration_ms, 1)
            print(f"[cold_vs_warm] cold_duration_ms={have_cold.duration_ms}")
            print(f"[cold_vs_warm] warm_duration_ms={have_warm.duration_ms}")
            print(f"[cold_vs_warm] speedup_ratio={speedup:.2f}x")
            return {"cold": have_cold, "warm": have_warm}
        if have_cold is not None and have_warm is None:
            wait_for_warm_available(base_url, 20)
        time.sleep(0.25)

    raise RuntimeError("could not observe both cold and warm dispatches for the same governed payload within 6 attempts")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"status=failed error={exc}", file=sys.stderr)
        raise SystemExit(1)
