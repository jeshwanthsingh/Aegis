#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

import run_canonical_demo as canonical


REPO_DIR = canonical.REPO_DIR
DEFAULT_CONFIG_PATH = canonical.DEFAULT_CONFIG_PATH
DEFAULT_BASE_URL = canonical.DEFAULT_BASE_URL
DEFAULT_RUNTIME_LOG_DIR = Path("/tmp/aegis-red-team-matrix")
DEPENDENCY_DENIED_MARKER = "PASS_dependency_fetch_denied"


@dataclass(slots=True)
class ScenarioResult:
    name: str
    passed: bool
    detail: str
    execution_id: str = ""
    proof_dir: str = ""
    verify_signal: str = ""


@dataclass(slots=True)
class InflightExecution:
    execution_id: str
    thread: threading.Thread
    errors: list[BaseException]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Aegis red-team and fault matrix v1.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to the repo-local Aegis config.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Aegis API base URL. The matrix manages its own runtime on this URL.")
    parser.add_argument("--warm-pool-size", type=int, default=1, help="Warm pool size override for the managed runtime.")
    parser.add_argument("--broker-token", default=canonical.DEFAULT_BROKER_TOKEN, help="Synthetic broker token used for the managed runtime.")
    parser.add_argument("--runtime-log-dir", default=str(DEFAULT_RUNTIME_LOG_DIR), help="Directory for managed runtime logs.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_url = args.base_url.rstrip("/")
    config_path = Path(args.config).resolve()
    runtime_log_dir = Path(args.runtime_log_dir).resolve()
    runtime_log_dir.mkdir(parents=True, exist_ok=True)
    go_bin = canonical.resolve_go_bin()
    cli_bin = canonical.resolve_cli_bin()
    verify_cmd = [str(cli_bin), "receipt", "verify"]

    print(f"matrix_base_url={base_url}")
    print(f"matrix_config={config_path}")
    print(f"matrix_cli={cli_bin}")
    print(f"matrix_verify_cmd={' '.join(verify_cmd)}")

    if canonical.runtime_health(base_url) is not None:
        raise RuntimeError(
            f"runtime already active at {base_url}. "
            "The fault matrix kills and restarts the daemon; stop the existing runtime first."
        )

    postgres = canonical.LocalPostgres(REPO_DIR / "db" / "schema.sql")
    postgres.__enter__()
    runtime1 = None
    runtime2 = None
    results: list[ScenarioResult] = []
    try:
        runtime1 = start_runtime(
            go_bin=go_bin,
            cli_bin=cli_bin,
            config_path=config_path,
            base_url=base_url,
            db_url=postgres.db_url,
            broker_token=args.broker_token,
            warm_pool_size=args.warm_pool_size,
            runtime_log=runtime_log_dir / "runtime-1.log",
        )

        allowed = canonical.run_governed_allow(base_url, verify_cmd)
        results.append(
            ScenarioResult(
                name="allowed_brokered_http_request",
                passed=True,
                detail="receipt verified with credential.request,credential.allowed and governed_action allow evidence",
                execution_id=allowed.execution_id,
                proof_dir=allowed.proof_dir,
                verify_signal="broker_events=credential.request,credential.allowed",
            )
        )

        denied = canonical.run_governed_deny(base_url, verify_cmd)
        results.append(
            ScenarioResult(
                name="denied_direct_egress",
                passed=True,
                detail="receipt verified with network_connect deny and direct_egress_denied marker",
                execution_id=denied.execution_id,
                proof_dir=denied.proof_dir,
                verify_signal="denial_marker=direct_egress_denied",
            )
        )

        dependency = run_dependency_fetch_denied(base_url, verify_cmd)
        results.append(
            ScenarioResult(
                name="denied_unapproved_dependency_fetch",
                passed=True,
                detail="receipt verified with dependency_fetch deny and governed_action_denied marker",
                execution_id=dependency.execution_id,
                proof_dir=dependency.proof_dir,
                verify_signal="governed_action_1=kind=dependency_fetch",
            )
        )

        assert_secret_not_disclosed(allowed, args.broker_token)
        results.append(
            ScenarioResult(
                name="broker_secret_non_disclosure",
                passed=True,
                detail="synthetic broker token not found in stdout, stderr, or proof bundle artifacts",
                execution_id=allowed.execution_id,
                proof_dir=allowed.proof_dir,
            )
        )

        workspace = canonical.run_workspace_flow(base_url, verify_cmd)
        results.append(
            ScenarioResult(
                name="workspace_delete_post_delete_failure",
                passed=True,
                detail="workspace create/write/read/delete succeeded and post-delete access failed honestly",
                execution_id=workspace["read"].execution_id,
                proof_dir=workspace["read"].proof_dir,
                verify_signal=f"workspace_id={extract_workspace_id(workspace['read'].verify_output)}",
            )
        )

        warm_orphans = capture_warm_orphans(base_url)
        killed_exec_id = str(uuid.uuid4())
        inflight = start_inflight_execution(base_url, killed_exec_id)
        wait_for_execution_status(
            postgres.db_url,
            killed_exec_id,
            {"guest_ready", "running", "finalizing"},
            timeout_seconds=45,
            inflight=inflight,
        )
        kill_orchestrator(postgres.db_url, config_path)
        runtime1.__exit__(None, None, None)
        runtime1 = None

        runtime2 = start_runtime(
            go_bin=go_bin,
            cli_bin=cli_bin,
            config_path=config_path,
            base_url=base_url,
            db_url=postgres.db_url,
            broker_token=args.broker_token,
            warm_pool_size=args.warm_pool_size,
            runtime_log=runtime_log_dir / "runtime-2.log",
        )

        reconciled = verify_reconciled_receipt(verify_cmd, killed_exec_id, postgres.db_url)
        results.append(
            ScenarioResult(
                name="daemon_kill_reconciled_receipt",
                passed=True,
                detail="in-flight execution was marked reconciled on restart and emitted a recovered_on_boot receipt",
                execution_id=killed_exec_id,
                proof_dir=reconciled.proof_dir,
                verify_signal="execution_status=reconciled",
            )
        )

        warm_cleanup_detail = verify_warm_orphan_cleanup(runtime_log_dir / "runtime-2.log", warm_orphans)
        results.append(
            ScenarioResult(
                name="warm_orphan_cleanup_on_restart",
                passed=True,
                detail=warm_cleanup_detail,
            )
        )

        abnormal = run_abnormal_receipt_verify_case(cli_bin, allowed.proof_dir)
        results.append(
            ScenarioResult(
                name="abnormal_receipt_verification_case",
                passed=True,
                detail=abnormal,
                proof_dir=allowed.proof_dir,
                verify_signal="artifact digest mismatch",
            )
        )
    finally:
        if runtime2 is not None:
            runtime2.__exit__(None, None, None)
        if runtime1 is not None:
            runtime1.__exit__(None, None, None)
        postgres.__exit__(None, None, None)

    print_summary(results)
    return 0 if all(result.passed for result in results) else 1


def start_runtime(
    *,
    go_bin: Path,
    cli_bin: Path,
    config_path: Path,
    base_url: str,
    db_url: str,
    broker_token: str,
    warm_pool_size: int,
    runtime_log: Path,
) -> canonical.LocalRuntime:
    runtime = canonical.LocalRuntime(
        go_bin=go_bin,
        cli_bin=cli_bin,
        config_path=config_path,
        base_url=base_url,
        db_url=db_url,
        runtime_log=runtime_log,
        warm_pool_size=warm_pool_size,
        broker_token=broker_token,
    )
    runtime.__enter__()
    return runtime


def dependency_fetch_denied_payload(port: int, execution_id: str) -> dict:
    code = f"""#!/usr/bin/env bash
set -euo pipefail
exec 3<>/dev/tcp/127.0.0.1/8888
printf 'GET http://127.0.0.1:{port}/pkg.whl HTTP/1.1\\r\\nHost: 127.0.0.1:{port}\\r\\nX-Aegis-Governed-Action: dependency_fetch\\r\\nConnection: close\\r\\n\\r\\n' >&3
response=''
while IFS= read -r line <&3; do
  response+="$line"$'\\n'
done || true
exec 3>&-
exec 3<&-
case "$response" in
  *'HTTP/1.1 403'*'broker denied:'*|*'HTTP/1.0 403'*'broker denied:'*)
    echo '{DEPENDENCY_DENIED_MARKER}'
    exit 0
    ;;
esac
echo 'FAIL_dependency_fetch_denied'
printf '%s\\n' "$response"
exit 1
"""
    return {
        "lang": "bash",
        "code": code,
        "timeout_ms": canonical.DEFAULT_TIMEOUT_MS,
        "profile": "standard",
        "intent": canonical.base_intent(
            execution_id=execution_id,
            language="bash",
            allow_network=True,
            allowed_ips=["127.0.0.1"],
            allowed_domains=[],
            allowed_binaries=["bash"],
            allow_shell=True,
            allowed_delegations=["github"],
            broker_domains=["127.0.0.1"],
            task_class="matrix_dependency_fetch_denied",
            declared_purpose="Prove unapproved dependency_fetch is denied with receipt evidence",
        ),
    }


def run_dependency_fetch_denied(base_url: str, verify_cmd: list[str]) -> canonical.ExecutionResult:
    with canonical.ProbeContext() as probe:
        execution_id = str(uuid.uuid4())
        result = canonical.execute(
            base_url,
            "dependency_fetch_denied",
            dependency_fetch_denied_payload(probe.port, execution_id),
            verify_cmd,
            expect_exit_code=0,
        )
        canonical.require_contains(str(result.response.get("stdout", "")), DEPENDENCY_DENIED_MARKER, label="dependency_fetch_denied stdout")
        if probe.observations:
            raise RuntimeError(f"dependency_fetch_denied: unexpected upstream probe request(s): {probe.observations}")
        canonical.require_contains(result.verify_output, "verification=verified", label="dependency_fetch_denied verify")
        canonical.require_contains(result.verify_output, "broker_events=credential.request,credential.denied", label="dependency_fetch_denied verify")
        canonical.require_contains(result.verify_output, "broker_denied_count=1", label="dependency_fetch_denied verify")
        canonical.require_contains(result.verify_output, "governed_action_1=kind=dependency_fetch", label="dependency_fetch_denied verify")
        canonical.require_contains(result.verify_output, "decision=deny", label="dependency_fetch_denied verify")
        canonical.require_contains(result.verify_output, "denial_marker=governed_action_denied", label="dependency_fetch_denied verify")
        canonical.print_case("dependency_fetch_denied", result)
        return result


def assert_secret_not_disclosed(result: canonical.ExecutionResult, secret: str) -> None:
    if secret in str(result.response.get("stdout", "")):
        raise RuntimeError("broker secret leaked into stdout")
    if secret in str(result.response.get("stderr", "")):
        raise RuntimeError("broker secret leaked into stderr")
    secret_bytes = secret.encode("utf-8")
    for path in Path(result.proof_dir).rglob("*"):
        if not path.is_file():
            continue
        if secret_bytes in path.read_bytes():
            raise RuntimeError(f"broker secret leaked into proof artifact {path}")


def extract_workspace_id(summary: str) -> str:
    for line in summary.splitlines():
        if line.startswith("workspace_id="):
            return line.split("=", 1)[1]
    return ""


def list_warm_orphan_paths() -> list[Path]:
    root = Path("/tmp/aegis")
    patterns = ("scratch-*.ext4", "fc-*.sock", "vsock-*.sock")
    found: list[Path] = []
    for pattern in patterns:
        found.extend(sorted(root.glob(pattern)))
    return found


def capture_warm_orphans(base_url: str) -> list[Path]:
    if not canonical.wait_for_warm_available(base_url, 30):
        raise RuntimeError("warm pool never became available before the restart fault scenario")
    deadline = time.time() + 20
    while time.time() < deadline:
        paths = list_warm_orphan_paths()
        if paths:
            print("warm_orphans_before_restart=" + ",".join(str(path) for path in paths))
            return paths
        time.sleep(0.25)
    raise RuntimeError("warm pool reported available but no warm orphan scratch/socket files were found")


def post_json(base_url: str, path: str, payload: dict, *, timeout: int = 90) -> dict:
    del timeout
    status, response = canonical.http_json(base_url, "POST", path, payload)
    if status != 200:
        raise RuntimeError(f"POST {path} returned {status}: {response}")
    return response


def inflight_payload(execution_id: str) -> dict:
    intent = canonical.base_intent(
        execution_id=execution_id,
        language="python",
        allow_network=False,
        allowed_ips=[],
        allowed_domains=[],
        allowed_binaries=["python3"],
        allow_shell=False,
        allowed_delegations=[],
        broker_domains=[],
        task_class="matrix_reconcile_after_kill",
        declared_purpose="Prove daemon kill during an in-flight execution reconciles honestly on restart",
    )
    intent["budgets"]["timeout_sec"] = 10
    intent["budgets"]["stdout_bytes"] = 8192
    return {
        "execution_id": execution_id,
        "lang": "python",
        "code": "import time\nprint('inflight-start', flush=True)\ntime.sleep(8)\nprint('inflight-end', flush=True)\n",
        "timeout_ms": 10000,
        "profile": "crunch",
        "intent": intent,
    }


def start_inflight_execution(base_url: str, execution_id: str) -> InflightExecution:
    errors: list[BaseException] = []

    def run_request() -> None:
        try:
            post_json(base_url, "/v1/execute", inflight_payload(execution_id), timeout=90)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    thread = threading.Thread(target=run_request, daemon=True)
    thread.name = f"inflight-{execution_id}"
    thread.start()
    return InflightExecution(execution_id=execution_id, thread=thread, errors=errors)


def psql_query(db_url: str, sql: str) -> str:
    completed = subprocess.run(
        [str(canonical.POSTGRES_PSQL), db_url, "-Atc", sql],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"psql query failed: {sql}\n{detail}")
    return completed.stdout.strip()


def wait_for_execution_status(
    db_url: str,
    execution_id: str,
    wanted: set[str],
    *,
    timeout_seconds: float,
    inflight: InflightExecution | None = None,
) -> str:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if inflight is not None and inflight.errors:
            raise RuntimeError(
                f"in-flight execute request failed before execution {execution_id} reached the store: "
                f"{inflight.errors[0]}"
            )
        status = psql_query(db_url, f"select status from executions where execution_id = '{execution_id}'")
        if status in wanted:
            print(f"inflight_execution_status={status}")
            return status
        if inflight is not None and not inflight.thread.is_alive() and not status:
            raise RuntimeError(
                f"in-flight execute request finished without creating execution {execution_id}; "
                "the request likely failed before the orchestrator accepted it"
            )
        time.sleep(0.25)
    raise RuntimeError(f"execution {execution_id} never reached one of {sorted(wanted)}")


def find_orchestrator_pid(db_url: str, config_path: Path) -> int:
    config_text = config_path.read_text()
    marker = 'orchestrator_bin: "'
    if marker not in config_text:
        raise RuntimeError(f"could not find orchestrator_bin in {config_path}")
    orchestrator_bin = config_text.split(marker, 1)[1].split('"', 1)[0]
    completed = subprocess.run(
        ["ps", "-eo", "pid=,args="],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"ps failed: {completed.stderr}")
    for line in completed.stdout.splitlines():
        line = line.strip()
        if orchestrator_bin in line and db_url in line:
            pid_str = line.split(None, 1)[0]
            return int(pid_str)
    raise RuntimeError(f"could not locate orchestrator pid for db_url={db_url}")


def kill_orchestrator(db_url: str, config_path: Path) -> None:
    pid = find_orchestrator_pid(db_url, config_path)
    os.kill(pid, signal.SIGKILL)
    print(f"killed_orchestrator_pid={pid}")
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    raise RuntimeError(f"orchestrator pid {pid} did not exit after SIGKILL")


def verify_reconciled_receipt(verify_cmd: list[str], execution_id: str, db_url: str) -> canonical.ExecutionResult:
    proof_dir = Path("/tmp/aegis/proofs") / execution_id
    deadline = time.time() + 45
    while time.time() < deadline:
        if (proof_dir / "receipt.dsse.json").is_file():
            break
        time.sleep(0.25)
    else:
        raise RuntimeError(f"reconciled proof bundle was not written for execution {execution_id}")

    status = wait_for_execution_status(db_url, execution_id, {"reconciled"}, timeout_seconds=10)
    if status != "reconciled":
        raise RuntimeError(f"execution {execution_id} was not marked reconciled")

    verify_output = canonical.verify_proof(verify_cmd, {"proof_dir": str(proof_dir)})
    canonical.require_contains(verify_output, "verification=verified", label="reconciled verify")
    canonical.require_contains(verify_output, "execution_status=reconciled", label="reconciled verify")
    canonical.require_contains(verify_output, "outcome=recovered_on_boot exit_code=-1", label="reconciled verify")
    canonical.require_contains(verify_output, "stderr.txt", label="reconciled verify")
    result = canonical.ExecutionResult(
        label="reconciled_receipt",
        response={"execution_id": execution_id, "proof_dir": str(proof_dir), "dispatch_path": "n/a", "duration_ms": 0},
        verify_output=verify_output,
    )
    canonical.print_case("reconciled_receipt", result)
    return result


def verify_warm_orphan_cleanup(runtime_log_path: Path, orphan_paths: list[Path]) -> str:
    still_present = [str(path) for path in orphan_paths if path.exists()]
    if still_present:
        raise RuntimeError(f"warm orphan path(s) survived restart: {still_present}")
    log_text = runtime_log_path.read_text(encoding="utf-8", errors="replace")
    if "reconcile_untracked_warm_orphan_removed" not in log_text:
        raise RuntimeError(f"restart log {runtime_log_path} did not record warm orphan reconciliation")
    return f"removed {len(orphan_paths)} warm orphan file(s) and logged reconcile_untracked_warm_orphan_removed"


def run_abnormal_receipt_verify_case(cli_bin: Path, proof_dir: str) -> str:
    tampered_root = Path(tempfile.mkdtemp(prefix="aegis-tampered-proof-"))
    tampered_bundle = tampered_root / "bundle"
    shutil.copytree(proof_dir, tampered_bundle)
    manifest = tampered_bundle / "output-manifest.json"
    manifest.write_text('{"version":"v1","execution_id":"tampered","output_truncated":false,"artifacts":[]}\n', encoding="utf-8")
    completed = subprocess.run(
        [str(cli_bin), "receipt", "verify", "--proof-dir", str(tampered_bundle)],
        cwd=REPO_DIR,
        text=True,
        capture_output=True,
        check=False,
    )
    shutil.rmtree(tampered_root, ignore_errors=True)
    if completed.returncode == 0:
        raise RuntimeError("tampered proof bundle unexpectedly verified")
    detail = completed.stderr.strip() or completed.stdout.strip()
    if "artifact digest mismatch for output-manifest.json" not in detail:
        raise RuntimeError(f"tampered proof verification failed for an unexpected reason: {detail}")
    print(f"[abnormal_receipt_verify] {detail}")
    return "tampered output-manifest.json failed verification with artifact digest mismatch"


def print_summary(results: list[ScenarioResult]) -> None:
    print("\nRed-Team & Fault Matrix v1")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"- [{status}] {result.name}: {result.detail}")
        if result.execution_id:
            print(f"  execution_id={result.execution_id}")
        if result.proof_dir:
            print(f"  proof_dir={result.proof_dir}")
        if result.verify_signal:
            print(f"  verify_signal={result.verify_signal}")
    print(f"matrix_status={'passed' if all(result.passed for result in results) else 'failed'}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"matrix_status=failed error={exc}", file=os.sys.stderr)
        raise SystemExit(1)
