#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import run_canonical_demo as canonical


REPO_DIR = canonical.REPO_DIR
DEFAULT_CONFIG_PATH = canonical.DEFAULT_CONFIG_PATH
DEFAULT_BASE_URL = canonical.DEFAULT_BASE_URL
DEFAULT_RUNTIME_LOG_DIR = Path("/tmp/aegis-overlap-pressure")
DEFAULT_WARM_POOL_SIZE = 1
DEFAULT_WORKER_POOL_SIZE = 2


@dataclass(slots=True)
class ScenarioResult:
    name: str
    passed: bool
    detail: str
    evidence: list[str] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Aegis overlap and pressure hardening v1 proof harness.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to the repo-local Aegis config.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Aegis API base URL. The harness manages its own runtime on this URL.")
    parser.add_argument("--warm-pool-size", type=int, default=DEFAULT_WARM_POOL_SIZE, help="Warm pool size override for the managed runtime.")
    parser.add_argument("--worker-pool-size", type=int, default=DEFAULT_WORKER_POOL_SIZE, help="Worker slot override for the managed runtime.")
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

    print(f"overlap_base_url={base_url}")
    print(f"overlap_config={config_path}")
    print(f"overlap_cli={cli_bin}")
    print(f"overlap_verify_cmd={' '.join(verify_cmd)}")

    if canonical.runtime_health(base_url) is not None:
        raise RuntimeError(
            f"runtime already active at {base_url}. "
            "Stop the existing runtime first so this harness can prove overlap behavior honestly."
        )

    postgres = canonical.LocalPostgres(REPO_DIR / "db" / "schema.sql")
    postgres.__enter__()
    runtime = None
    results: list[ScenarioResult] = []
    try:
        runtime = canonical.LocalRuntime(
            go_bin=go_bin,
            cli_bin=cli_bin,
            config_path=config_path,
            base_url=base_url,
            db_url=postgres.db_url,
            runtime_log=runtime_log_dir / "runtime.log",
            warm_pool_size=args.warm_pool_size,
            worker_pool_size=args.worker_pool_size,
            broker_token=args.broker_token,
        )
        runtime.__enter__()

        results.append(run_concurrent_governed_mix(base_url, verify_cmd))
        results.append(run_broker_overlap_no_secret_bleed(base_url, verify_cmd, args.broker_token))
        results.append(run_workspace_overlap_contract(base_url, verify_cmd))
        results.append(run_mixed_pressure_and_saturation(base_url, verify_cmd))
    finally:
        if runtime is not None:
            runtime.__exit__(None, None, None)
        postgres.__exit__(None, None, None)

    print_summary(results)
    return 0 if all(result.passed for result in results) else 1


def governed_allow_overlap_payload(port: int, execution_id: str, *, path: str, marker: str, sleep_seconds: int = 1) -> dict:
    code = f"""#!/usr/bin/env bash
set -euo pipefail
read -r -t {sleep_seconds} _ </dev/null || true
exec 3<>/dev/tcp/127.0.0.1/8888
printf 'GET http://127.0.0.1:{port}{path} HTTP/1.1\\r\\nHost: 127.0.0.1:{port}\\r\\nConnection: close\\r\\n\\r\\n' >&3
response=''
while IFS= read -r line <&3; do
  response+="$line"$'\\n'
done || true
exec 3>&-
exec 3<&-
case "$response" in
  *'HTTP/1.1 200'*auth_present=true*|*'HTTP/1.0 200'*auth_present=true*)
    echo '{marker}'
    exit 0
    ;;
esac
echo 'FAIL_overlap_broker_allow'
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
            task_class="overlap_broker_allow",
            declared_purpose="Prove brokered http_request attribution stays correct under overlap",
        ),
    }


def governed_deny_overlap_payload(execution_id: str, *, marker: str, sleep_seconds: int = 1) -> dict:
    code = f"""import socket, time
time.sleep({sleep_seconds})
s = socket.socket()
s.settimeout(2)
try:
    rc = s.connect_ex(("1.2.3.4", 4444))
    if rc == 0:
        print("BAD_connected")
        raise SystemExit(1)
    print("{marker}")
finally:
    try:
        s.close()
    except Exception:
        pass
"""
    return {
        "lang": "python",
        "code": code,
        "timeout_ms": canonical.DEFAULT_TIMEOUT_MS,
        "profile": "standard",
        "intent": canonical.base_intent(
            execution_id=execution_id,
            language="python",
            allow_network=False,
            allowed_ips=[],
            allowed_domains=[],
            allowed_binaries=["python3"],
            allow_shell=False,
            allowed_delegations=[],
            broker_domains=[],
            task_class="overlap_governed_deny",
            declared_purpose="Prove direct egress deny attribution stays correct under overlap",
        ),
    }


def governed_allow_python_payload(port: int, execution_id: str, *, path: str, marker: str, sleep_seconds: int) -> dict:
    code = f"""import socket, time
time.sleep({sleep_seconds})
request = (
    "GET http://127.0.0.1:{port}{path} HTTP/1.1\\r\\n"
    "Host: 127.0.0.1:{port}\\r\\n"
    "Connection: close\\r\\n\\r\\n"
).encode()
s = socket.create_connection(("127.0.0.1", 8888), timeout=5)
try:
    s.sendall(request)
    chunks = []
    while True:
        data = s.recv(4096)
        if not data:
            break
        chunks.append(data)
finally:
    s.close()
response = b"".join(chunks).decode("utf-8", "replace")
if "auth_present=true" in response and ("HTTP/1.1 200" in response or "HTTP/1.0 200" in response):
    print("{marker}")
    raise SystemExit(0)
print("FAIL_pressure_broker_allow")
print(response)
raise SystemExit(1)
"""
    return {
        "lang": "python",
        "code": code,
        "timeout_ms": canonical.DEFAULT_TIMEOUT_MS,
        "profile": "standard",
        "intent": canonical.base_intent(
            execution_id=execution_id,
            language="python",
            allow_network=True,
            allowed_ips=["127.0.0.1"],
            allowed_domains=[],
            allowed_binaries=["python3"],
            allow_shell=False,
            allowed_delegations=["github"],
            broker_domains=["127.0.0.1"],
            task_class="pressure_broker_allow",
            declared_purpose="Prove a warm brokered execution stays honest under slot pressure",
        ),
    }


def workspace_write_payload(execution_id: str, workspace_id: str, *, marker: str, content: str, sleep_seconds: int = 1) -> dict:
    code = f"""from pathlib import Path
import time
time.sleep({sleep_seconds})
target = Path("/workspace/shared.txt")
target.write_text("{content}\\n")
print("{marker}")
"""
    return canonical.workspace_payload(
        execution_id,
        workspace_id,
        code,
        task_class="overlap_workspace_write",
        purpose="Write a workspace file under overlap pressure",
    )


def workspace_read_payload(execution_id: str, workspace_id: str, *, marker: str, expected_content: str) -> dict:
    code = f"""from pathlib import Path
target = Path("/workspace/shared.txt")
value = target.read_text().strip()
if value != "{expected_content}":
    raise SystemExit(f"unexpected workspace contents: {{value!r}}")
print("{marker}")
print(value)
"""
    return canonical.workspace_payload(
        execution_id,
        workspace_id,
        code,
        task_class="overlap_workspace_read",
        purpose="Read a workspace file after an overlapped write",
    )


def short_python_payload(execution_id: str, *, marker: str) -> dict:
    return {
        "lang": "python",
        "code": f'print("{marker}")\n',
        "timeout_ms": canonical.DEFAULT_TIMEOUT_MS,
        "profile": "standard",
        "intent": canonical.base_intent(
            execution_id=execution_id,
            language="python",
            allow_network=False,
            allowed_ips=[],
            allowed_domains=[],
            allowed_binaries=["python3"],
            allow_shell=False,
            allowed_delegations=[],
            broker_domains=[],
            task_class="overlap_short_python",
            declared_purpose="Prove pool saturation is reported honestly",
        ),
    }


def assert_secret_not_disclosed(result: canonical.ExecutionResult, secret: str) -> None:
    if secret in str(result.response.get("stdout", "")):
        raise RuntimeError(f"{result.label}: broker secret leaked into stdout")
    if secret in str(result.response.get("stderr", "")):
        raise RuntimeError(f"{result.label}: broker secret leaked into stderr")
    secret_bytes = secret.encode("utf-8")
    for path in Path(result.proof_dir).rglob("*"):
        if path.is_file() and secret_bytes in path.read_bytes():
            raise RuntimeError(f"{result.label}: broker secret leaked into proof artifact {path}")


def submit_execute(
    executor: concurrent.futures.Executor,
    *,
    base_url: str,
    label: str,
    payload: dict,
    verify_cmd: list[str],
    expect_exit_code: int | None = None,
) -> concurrent.futures.Future[canonical.ExecutionResult]:
    return executor.submit(canonical.execute, base_url, label, payload, verify_cmd, expect_exit_code=expect_exit_code)


def wait_for_ready_status(base_url: str, *, status_code: int, timeout_seconds: float) -> tuple[int, dict]:
    deadline = time.time() + timeout_seconds
    last: tuple[int, dict] = (0, {})
    while time.time() < deadline:
        last = canonical.http_json(base_url, "GET", "/ready")
        if last[0] == status_code:
            return last
        time.sleep(0.1)
    raise RuntimeError(f"/ready did not reach {status_code} within {timeout_seconds}s: last={last}")


def create_workspace(base_url: str, workspace_id: str) -> None:
    _, payload = canonical.http_json(base_url, "POST", f"/v1/workspaces/{workspace_id}", expected_status=201)
    if payload.get("status") != "created":
        raise RuntimeError(f"workspace create failed for {workspace_id}: {payload}")


def delete_workspace(base_url: str, workspace_id: str) -> None:
    canonical.http_json(base_url, "DELETE", f"/v1/workspaces/{workspace_id}", expected_status=200)


def run_concurrent_governed_mix(base_url: str, verify_cmd: list[str]) -> ScenarioResult:
    with canonical.ProbeContext() as probe, concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        allow_marker = "PASS_overlap_allow"
        deny_marker = "PASS_overlap_deny"
        allow_future = submit_execute(
            executor,
            base_url=base_url,
            label="overlap_allow",
            payload=governed_allow_overlap_payload(probe.port, str(uuid.uuid4()), path="/mix-allow", marker=allow_marker),
            verify_cmd=verify_cmd,
            expect_exit_code=0,
        )
        deny_future = submit_execute(
            executor,
            base_url=base_url,
            label="overlap_deny",
            payload=governed_deny_overlap_payload(str(uuid.uuid4()), marker=deny_marker),
            verify_cmd=verify_cmd,
        )
        allow = allow_future.result(timeout=60)
        deny = deny_future.result(timeout=60)

    canonical.require_contains(str(allow.response.get("stdout", "")), allow_marker, label="overlap_allow stdout")
    canonical.require_contains(str(deny.response.get("stdout", "")), deny_marker, label="overlap_deny stdout")
    deny_exit_reason = str(deny.response.get("exit_reason", ""))
    if deny_exit_reason not in {"completed", "divergence_terminated"}:
        raise RuntimeError(f"overlap_deny: unexpected exit_reason={deny_exit_reason!r}; response={deny.response}")
    canonical.require_contains(allow.verify_output, "governed_action_1=kind=http_request", label="overlap_allow verify")
    canonical.require_contains(allow.verify_output, "decision=allow", label="overlap_allow verify")
    canonical.require_contains(deny.verify_output, "governed_action_1=kind=network_connect", label="overlap_deny verify")
    canonical.require_contains(deny.verify_output, "decision=deny", label="overlap_deny verify")
    canonical.require_contains(deny.verify_output, "denial_marker=direct_egress_denied", label="overlap_deny verify")
    if len(probe.observations) != 1 or probe.observations[0].path != "/mix-allow" or not probe.observations[0].auth_present:
        raise RuntimeError(f"concurrent_governed_mix: unexpected probe observations {probe.observations}")

    canonical.print_case("overlap_allow", allow)
    canonical.print_case("overlap_deny", deny)
    return ScenarioResult(
        name="concurrent_governed_allow_deny_mix",
        passed=True,
        detail="brokered allow and direct deny stayed attributable under overlap",
        evidence=[
            f"allow_execution_id={allow.execution_id}",
            f"deny_execution_id={deny.execution_id}",
            f"allow_proof_dir={allow.proof_dir}",
            f"deny_proof_dir={deny.proof_dir}",
        ],
    )


def run_broker_overlap_no_secret_bleed(base_url: str, verify_cmd: list[str], broker_token: str) -> ScenarioResult:
    with canonical.ProbeContext() as probe, concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        alpha_marker = "PASS_overlap_broker_alpha"
        beta_marker = "PASS_overlap_broker_beta"
        alpha_future = submit_execute(
            executor,
            base_url=base_url,
            label="overlap_broker_alpha",
            payload=governed_allow_overlap_payload(probe.port, str(uuid.uuid4()), path="/alpha", marker=alpha_marker),
            verify_cmd=verify_cmd,
            expect_exit_code=0,
        )
        beta_future = submit_execute(
            executor,
            base_url=base_url,
            label="overlap_broker_beta",
            payload=governed_allow_overlap_payload(probe.port, str(uuid.uuid4()), path="/beta", marker=beta_marker),
            verify_cmd=verify_cmd,
            expect_exit_code=0,
        )
        alpha = alpha_future.result(timeout=60)
        beta = beta_future.result(timeout=60)

    alpha_stdout = str(alpha.response.get("stdout", ""))
    beta_stdout = str(beta.response.get("stdout", ""))
    canonical.require_contains(alpha_stdout, alpha_marker, label="overlap_broker_alpha stdout")
    canonical.require_contains(beta_stdout, beta_marker, label="overlap_broker_beta stdout")
    if beta_marker in alpha_stdout or alpha_marker in beta_stdout:
        raise RuntimeError("broker overlap outputs crossed between executions")
    canonical.require_contains(alpha.verify_output, "broker_events=credential.request,credential.allowed", label="overlap_broker_alpha verify")
    canonical.require_contains(beta.verify_output, "broker_events=credential.request,credential.allowed", label="overlap_broker_beta verify")
    assert_secret_not_disclosed(alpha, broker_token)
    assert_secret_not_disclosed(beta, broker_token)
    observed_paths = sorted(observation.path for observation in probe.observations)
    if observed_paths != ["/alpha", "/beta"] or not all(observation.auth_present for observation in probe.observations):
        raise RuntimeError(f"broker overlap probe mismatch: {probe.observations}")

    canonical.print_case("overlap_broker_alpha", alpha)
    canonical.print_case("overlap_broker_beta", beta)
    return ScenarioResult(
        name="broker_overlap_no_secret_bleed",
        passed=True,
        detail="two simultaneous brokered requests stayed isolated and did not leak the broker secret",
        evidence=[
            f"alpha_execution_id={alpha.execution_id}",
            f"beta_execution_id={beta.execution_id}",
            f"alpha_proof_dir={alpha.proof_dir}",
            f"beta_proof_dir={beta.proof_dir}",
        ],
    )


def run_workspace_overlap_contract(base_url: str, verify_cmd: list[str]) -> ScenarioResult:
    workspace_a = f"overlap-a-{uuid.uuid4().hex[:8]}"
    workspace_b = f"overlap-b-{uuid.uuid4().hex[:8]}"
    create_workspace(base_url, workspace_a)
    create_workspace(base_url, workspace_b)
    evidence: list[str] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            write_a_future = submit_execute(
                executor,
                base_url=base_url,
                label="workspace_a_write",
                payload=workspace_write_payload(str(uuid.uuid4()), workspace_a, marker="PASS_workspace_a_write", content="workspace-a"),
                verify_cmd=verify_cmd,
                expect_exit_code=0,
            )
            time.sleep(0.2)
            overlap_status, overlap_payload = canonical.http_json(
                base_url,
                "POST",
                "/v1/execute",
                canonical.workspace_payload(
                    str(uuid.uuid4()),
                    workspace_a,
                    'print("should_not_run")\n',
                    task_class="overlap_workspace_reject",
                    purpose="Confirm same-workspace overlap is rejected before admission",
                ),
                expected_status=409,
            )
            write_b_future = submit_execute(
                executor,
                base_url=base_url,
                label="workspace_b_write",
                payload=workspace_write_payload(str(uuid.uuid4()), workspace_b, marker="PASS_workspace_b_write", content="workspace-b"),
                verify_cmd=verify_cmd,
                expect_exit_code=0,
            )
            write_a = write_a_future.result(timeout=60)
            write_b = write_b_future.result(timeout=60)

        error = overlap_payload.get("error") or {}
        if overlap_status != 409 or error.get("code") != "workspace_busy":
            raise RuntimeError(f"same-workspace overlap rejection mismatch: status={overlap_status} payload={overlap_payload}")
        if "execution_id" in overlap_payload or "proof_dir" in overlap_payload or "receipt_path" in overlap_payload:
            raise RuntimeError(f"same-workspace overlap fabricated admission evidence: {overlap_payload}")

        read_a = canonical.execute(
            base_url,
            "workspace_a_read",
            workspace_read_payload(str(uuid.uuid4()), workspace_a, marker="PASS_workspace_a_read", expected_content="workspace-a"),
            verify_cmd,
            expect_exit_code=0,
        )
        read_b = canonical.execute(
            base_url,
            "workspace_b_read",
            workspace_read_payload(str(uuid.uuid4()), workspace_b, marker="PASS_workspace_b_read", expected_content="workspace-b"),
            verify_cmd,
            expect_exit_code=0,
        )

        canonical.print_case("workspace_a_write", write_a)
        canonical.print_case("workspace_b_write", write_b)
        canonical.print_case("workspace_a_read", read_a)
        canonical.print_case("workspace_b_read", read_b)
        evidence.extend(
            [
                f"workspace_a={workspace_a}",
                f"workspace_b={workspace_b}",
                f"workspace_busy_code={error.get('code')}",
                f"workspace_a_proof_dir={write_a.proof_dir}",
                f"workspace_b_proof_dir={write_b.proof_dir}",
            ]
        )
        return ScenarioResult(
            name="workspace_overlap_contract",
            passed=True,
            detail="different workspaces ran concurrently while same-workspace overlap was rejected before admission",
            evidence=evidence,
        )
    finally:
        for workspace_id in (workspace_a, workspace_b):
            try:
                delete_workspace(base_url, workspace_id)
            except Exception:
                pass


def run_mixed_pressure_and_saturation(base_url: str, verify_cmd: list[str]) -> ScenarioResult:
    if not canonical.wait_for_warm_available(base_url, 30):
        raise RuntimeError("warm pool did not report an available VM before the pressure scenario")

    workspace_id = f"pressure-{uuid.uuid4().hex[:8]}"
    create_workspace(base_url, workspace_id)
    evidence: list[str] = [f"workspace_id={workspace_id}"]
    try:
        with canonical.ProbeContext() as probe, concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            warm_future = submit_execute(
                executor,
                base_url=base_url,
                label="pressure_warm_allow",
                payload=governed_allow_python_payload(
                    probe.port,
                    str(uuid.uuid4()),
                    path="/pressure-warm",
                    marker="PASS_pressure_warm",
                    sleep_seconds=3,
                ),
                verify_cmd=verify_cmd,
                expect_exit_code=0,
            )
            cold_future = submit_execute(
                executor,
                base_url=base_url,
                label="pressure_cold_workspace",
                payload=workspace_write_payload(
                    str(uuid.uuid4()),
                    workspace_id,
                    marker="PASS_pressure_cold",
                    content="pressure-cold",
                    sleep_seconds=3,
                ),
                verify_cmd=verify_cmd,
                expect_exit_code=0,
            )

            ready_status, ready_payload = wait_for_ready_status(base_url, status_code=503, timeout_seconds=20)
            if ready_payload.get("worker_slots_available") != 0:
                raise RuntimeError(f"/ready reported saturation with unexpected slots payload: {ready_payload}")

            reject_status, reject_payload = canonical.http_json(
                base_url,
                "POST",
                "/v1/execute",
                short_python_payload(str(uuid.uuid4()), marker="PASS_should_not_admit"),
                expected_status=429,
            )
            if reject_payload.get("error", {}).get("code") != "too_many_requests":
                raise RuntimeError(f"saturation reject mismatch: status={reject_status} payload={reject_payload}")

            warm = warm_future.result(timeout=60)
            cold = cold_future.result(timeout=60)

        canonical.print_case("pressure_warm_allow", warm)
        canonical.print_case("pressure_cold_workspace", cold)
        if warm.dispatch_path != "warm":
            raise RuntimeError(f"expected warm dispatch under pressure, got {warm.dispatch_path!r}")
        if cold.dispatch_path != "cold":
            raise RuntimeError(f"expected cold dispatch for workspace-backed request, got {cold.dispatch_path!r}")
        if cold.response.get("cold_fallback_reason") != "workspace_attached":
            raise RuntimeError(f"expected workspace cold fallback reason, got {cold.response}")
        if len(probe.observations) != 1 or probe.observations[0].path != "/pressure-warm" or not probe.observations[0].auth_present:
            raise RuntimeError(f"pressure probe mismatch: {probe.observations}")

        ready_after_status, ready_after_payload = wait_for_ready_status(base_url, status_code=200, timeout_seconds=20)
        if ready_after_payload.get("worker_slots_available", 0) <= 0:
            raise RuntimeError(f"/ready did not recover worker slots after pressure: {ready_after_payload}")

        evidence.extend(
            [
                f"ready_saturated_status={ready_status}",
                f"ready_saturated_slots={ready_payload.get('worker_slots_available')}/{ready_payload.get('worker_slots_total')}",
                f"saturation_reject_code={reject_payload.get('error', {}).get('code')}",
                f"warm_execution_id={warm.execution_id}",
                f"cold_execution_id={cold.execution_id}",
                f"warm_dispatch_path={warm.dispatch_path}",
                f"cold_dispatch_path={cold.dispatch_path}",
                f"warm_proof_dir={warm.proof_dir}",
                f"cold_proof_dir={cold.proof_dir}",
                f"ready_recovered_status={ready_after_status}",
            ]
        )
        return ScenarioResult(
            name="mixed_cold_warm_pressure_and_saturation",
            passed=True,
            detail="warm/cold overlap stayed honest and worker-slot saturation was surfaced explicitly",
            evidence=evidence,
        )
    finally:
        try:
            delete_workspace(base_url, workspace_id)
        except Exception:
            pass


def print_summary(results: list[ScenarioResult]) -> None:
    print("\nOverlap & Pressure Hardening v1")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"- [{status}] {result.name}: {result.detail}")
        for line in result.evidence:
            print(f"  {line}")
    print(f"matrix_status={'passed' if all(result.passed for result in results) else 'failed'}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"matrix_status=failed error={exc}", file=os.sys.stderr)
        raise SystemExit(1)
