#!/usr/bin/env python3
from __future__ import annotations

import argparse
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
    sub.add_parser("clean", help="run the clean execution demo")
    sub.add_parser("exfil-denied", help="run the exfil denied demo")
    sub.add_parser("broker-success", help="run the brokered outbound success demo")
    args = parser.parse_args()

    try:
        if args.command == "up":
            return demo_up()
        if args.command == "down":
            return demo_down()
        if args.command == "status":
            return demo_status()
        if args.command == "clean":
            return demo_clean()
        if args.command == "exfil-denied":
            return demo_exfil_denied()
        if args.command == "broker-success":
            return demo_broker_success()
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
            print_next_steps()
            return 0
        raise DemoError(
            f"Aegis is already healthy at {DEFAULT_API_URL} but is not owned by the demo state at {STATE_PATH}. "
            "Reuse that runtime or stop it before running demo_up.sh."
        )

    cleanup_from_state()
    ensure_prerequisites()
    state = start_demo_runtime()
    save_state(state)
    print("status=started")
    print(f"api_url={state.api_url}")
    print(f"runtime_log={state.runtime_log}")
    print(f"postgres_url={state.postgres_url}")
    print(f"proof_root={state.proof_root}")
    print_next_steps()
    return 0


def demo_down() -> int:
    state = load_state()
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
    return 0


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


@dataclass(slots=True)
class DemoResult:
    run_output: str
    proof_dir: str
    show_output: str
    verify_output: str
    summary: dict[str, str]


def run_cli_demo(
    *,
    label: str,
    run_args: list[str],
    expected_verify: dict[str, str],
    contains_verify: list[str] | None = None,
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

    return DemoResult(
        run_output=combined_output,
        proof_dir=proof_dir,
        show_output=show_proc.stdout + show_proc.stderr,
        verify_output=verify_output,
        summary=parse_summary(verify_output),
    )


def print_demo_result(label: str, result: DemoResult) -> None:
    filtered_output = extract_user_output(result.run_output)
    execution_id = result.summary.get("execution_id", "unknown")
    receipt_bits = [
        f"result_class={result.summary.get('result_class', 'unknown')}",
        f"outcome={result.summary.get('outcome', 'unknown')}",
        f"policy_digest={result.summary.get('policy_digest', 'unknown')}",
    ]
    if "denial_marker" in result.summary:
        receipt_bits.append(f"denial_marker={result.summary['denial_marker']}")
    if "broker_allowed_count" in result.summary and result.summary["broker_allowed_count"] != "0":
        receipt_bits.append(f"broker_allowed_count={result.summary['broker_allowed_count']}")
    print(f"demo={label}")
    if filtered_output:
        print("stdout:")
        for line in filtered_output.splitlines():
            print(f"  {line}")
    print(f"execution_id={execution_id}")
    print(f"proof_dir={result.proof_dir}")
    print("receipt_summary=" + " ".join(receipt_bits))
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
    if runtime_health(DEFAULT_API_URL):
        return
    raise DemoError("demo runtime is not healthy at http://127.0.0.1:8080; run ./scripts/demo_up.sh first")


def start_demo_runtime() -> DemoState:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    PROOF_ROOT.mkdir(parents=True, exist_ok=True)
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


def ensure_prerequisites() -> None:
    check_kvm()
    resolve_firecracker()
    require_file(POLICY_PATH, "default policy")
    require_file(SCHEMA_PATH, "database schema")
    require_file(ASSETS_DIR, "assets directory")
    require_file(KERNEL_PATH, "kernel image")
    require_file(ROOTFS_PATH, "rootfs image")
    resolve_go_bin()
    find_postgres_tool("initdb")
    find_postgres_tool("pg_ctl")
    find_postgres_tool("psql")


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


def cli_env(state: DemoState) -> dict[str, str]:
    env = os.environ.copy()
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
    print("next=./scripts/demo_clean.sh")
    print("next=./scripts/demo_exfil_denied.sh")
    print("next=./scripts/demo_broker_success.sh")
    print("next=./scripts/demo_status.sh")
    print("next=./scripts/demo_down.sh")


if __name__ == "__main__":
    raise SystemExit(main())
