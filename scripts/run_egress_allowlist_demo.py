#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
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
from pathlib import Path

import aegis_demo


OUTPUT_ROOT = aegis_demo.REPO_DIR / "scripts" / "demo_output" / "egress_allowlist"
POLICY_PATH = aegis_demo.STATE_DIR / "egress-allowlist-policy.yaml"
MARKER_PATH = aegis_demo.STATE_DIR / "egress-allowlist-runtime.json"
DEFAULT_TIMEOUT_MS = 10000
HOST_CHECK_TIMEOUT = 10
SUBPROCESS_TIMEOUT = 60
INTENT_EXTRA_READ_PATHS = ["/usr/bin", "/tmp"]
EXPECTED_BLOCKED_TARGETS = {
    "tcp://1.1.1.1:443": "ip",
    "dns:evil-attacker.example.com": "fqdn",
    "tcp://10.0.0.0/8": "rfc1918",
}
EXPECTED_BLOCKED_KIND_ORDER = ["ip", "fqdn", "rfc1918"]
EXPECTED_BLOCKED_KINDS = frozenset(EXPECTED_BLOCKED_KIND_ORDER)
EXPECTED_BROKER_URL = "https://api.github.com/zen"
EXPECTED_BROKER_DOMAIN = "api.github.com"


class DemoFailure(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class PhaseSpec:
    name: str
    result_label: str
    code: str


class Runner:
    def __init__(self) -> None:
        self.started_runtime = False
        self.reused_runtime = False
        self.summary_path = allocate_summary_path()
        self._policy_hash = ""
        self._previous_handlers: dict[int, object] = {}
        self._phase_summaries: list[dict[str, object]] = []

    def run(self) -> int:
        started = time.monotonic()
        summary_doc: dict[str, object] | None = None
        try:
            self.install_signal_handlers()
            print_banner(self.summary_path)
            self.ensure_host_reaches_github()
            self.ensure_network_execution_privileges()
            state = self.ensure_runtime()
            for spec in build_phase_specs():
                phase_summary = self.execute_phase(state, spec)
                self._phase_summaries.append(phase_summary)
                self.print_phase_summary(phase_summary)
                self.assert_phase_success(phase_summary)
            summary_doc = self.build_run_summary(elapsed_seconds=time.monotonic() - started)
            write_json(self.summary_path, summary_doc)
            print("overall=pass")
            print(f"summary_json={self.summary_path}")
            return 0
        except SystemExit:
            raise
        except Exception as exc:  # noqa: BLE001
            summary_doc = self.build_failure_summary(error=str(exc), elapsed_seconds=time.monotonic() - started)
            write_json(self.summary_path, summary_doc)
            print(f"FAIL: {exc}")
            print(f"summary_json={self.summary_path}")
            return 1
        finally:
            self.restore_signal_handlers()

    def install_signal_handlers(self) -> None:
        for signum in (signal.SIGINT, signal.SIGTERM):
            self._previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, self.handle_signal)

    def restore_signal_handlers(self) -> None:
        for signum, handler in self._previous_handlers.items():
            signal.signal(signum, handler)
        self._previous_handlers.clear()

    def handle_signal(self, signum: int, _frame) -> None:
        name = signal.Signals(signum).name
        print(f"signal={name} cleanup=starting")
        try:
            self.cleanup_managed_runtime()
        finally:
            print(f"FAIL: interrupted by {name}")
            raise SystemExit(130)

    def ensure_host_reaches_github(self) -> None:
        try:
            with socket.create_connection((EXPECTED_BROKER_DOMAIN, 443), timeout=HOST_CHECK_TIMEOUT):
                pass
        except OSError as exc:
            raise DemoFailure("host cannot reach api.github.com; check host network") from exc
        print("host_check=api.github.com:443 reachable")

    def ensure_network_execution_privileges(self) -> None:
        if os.geteuid() == 0:
            print("network_privileges=root")
            return
        if not Path("/dev/net/tun").exists():
            raise DemoFailure("/dev/net/tun is missing; host cannot run networked Aegis executions")
        getcap = shutil.which("getcap")
        if getcap is None:
            raise DemoFailure(
                "orchestrator cannot create TAP devices.\n"
                "The orchestrator binary needs cap_net_admin AND ambient caps\n"
                "must be raised at startup.\n"
                "Fix with:\n\n"
                "    make setcap\n\n"
                "Then re-run this demo. See docs/setup-local.md for details."
            )
        completed = run_command(
            [getcap, str(aegis_demo.ORCH_BIN)],
            label="orchestrator capability probe",
            timeout=10,
        )
        if "cap_net_admin" not in (completed.stdout + completed.stderr):
            raise DemoFailure(
                "orchestrator cannot create TAP devices.\n"
                "The orchestrator binary needs cap_net_admin AND ambient caps\n"
                "must be raised at startup.\n"
                "Fix with:\n\n"
                "    make setcap\n\n"
                "Then re-run this demo. See docs/setup-local.md for details."
            )
        print("network_privileges=cap_net_admin")

    def ensure_runtime(self) -> aegis_demo.DemoState:
        aegis_demo.STATE_DIR.mkdir(parents=True, exist_ok=True)
        policy_text = build_policy_text()
        self._policy_hash = hashlib.sha256(policy_text.encode("utf-8")).hexdigest()
        current_state = aegis_demo.load_state()
        healthy = aegis_demo.runtime_health(aegis_demo.DEFAULT_API_URL)
        marker = load_marker()

        if healthy and current_state is None:
            raise DemoFailure(
                f"Aegis is already healthy at {aegis_demo.DEFAULT_API_URL} but is not owned by the demo state at {aegis_demo.STATE_PATH}; stop it before running this demo"
            )

        if healthy and current_state is not None and marker is not None and marker.get("policy_sha256") == self._policy_hash:
            self.reused_runtime = True
            print("runtime_mode=reused")
            print(f"api_url={current_state.api_url}")
            print(f"proof_root={current_state.proof_root}")
            return current_state

        if current_state is not None or healthy:
            print("runtime_mode=restart_for_egress_allowlist_policy")
            aegis_demo.cleanup_from_state()
            remove_marker()

        POLICY_PATH.write_text(policy_text, encoding="utf-8")
        state = start_runtime_with_policy(POLICY_PATH, self._policy_hash)
        self.started_runtime = True
        print("runtime_mode=started")
        print(f"api_url={state.api_url}")
        print(f"proof_root={state.proof_root}")
        return state

    def cleanup_managed_runtime(self) -> None:
        marker = load_marker()
        if marker is None or marker.get("policy_sha256") != self._policy_hash:
            return
        aegis_demo.cleanup_from_state()
        remove_marker()

    def execute_phase(self, state: aegis_demo.DemoState, spec: PhaseSpec) -> dict[str, object]:
        started = time.monotonic()
        execution_id = str(uuid.uuid4())
        payload = {
            "execution_id": execution_id,
            "lang": "python",
            "code": spec.code,
            "timeout_ms": DEFAULT_TIMEOUT_MS,
            "intent": build_intent(execution_id),
        }
        status, response = http_json(state.api_url, "POST", "/v1/execute", payload, expected_status=200)
        if status != 200:
            raise DemoFailure(f"{spec.name}: execute returned unexpected status {status}: {response}")
        if str(response.get("error", "")).strip():
            raise DemoFailure(f"{spec.name}: execution failed: {response['error']}")
        receipt_path = str(response.get("receipt_path", "")).strip()
        proof_dir = str(response.get("proof_dir", "")).strip()
        if receipt_path == "" or proof_dir == "":
            raise DemoFailure(f"{spec.name}: execution response missing receipt paths: {response}")
        response["execution_id"] = execution_id
        response["receipt_path"] = receipt_path
        response["proof_dir"] = proof_dir
        verify_output = self.verify_receipt_offline(state, response)
        receipt_doc = load_signed_receipt(receipt_path)
        schema_validator = self.validate_predicate_schema(receipt_doc["statement"]["predicate"])
        return self.build_phase_summary(
            spec=spec,
            result=response,
            receipt_doc=receipt_doc,
            verify_output=verify_output,
            schema_validator=schema_validator,
            elapsed_seconds=time.monotonic() - started,
        )

    def verify_receipt_offline(self, state: aegis_demo.DemoState, response: dict[str, object]) -> str:
        cli = aegis_demo.require_file(aegis_demo.CLI_BIN, "repo-local aegis CLI binary")
        proof_dir = str(response["proof_dir"])
        completed = run_command(
            [str(cli), "receipt", "verify", "--proof-dir", proof_dir],
            label="offline receipt verify",
            cwd=aegis_demo.REPO_DIR,
            env=aegis_demo.cli_env(state),
            timeout=SUBPROCESS_TIMEOUT,
        )
        output = completed.stdout + completed.stderr
        verify_summary = aegis_demo.parse_summary(output)
        if verify_summary.get("verification") != "verified":
            raise DemoFailure(f"offline receipt verification did not succeed:\n{output}")
        return output

    def validate_predicate_schema(self, predicate: dict[str, object]) -> str:
        validator = shutil.which("jsonschema")
        if validator:
            command = [validator, "-i"]
            validator_name = validator
        else:
            command = [sys.executable, "-m", "jsonschema", "-i"]
            validator_name = f"{sys.executable} -m jsonschema"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            instance_path = Path(handle.name)
            json.dump(predicate, handle, indent=2, sort_keys=True)
        try:
            run_command(
                [*command, str(instance_path), str(aegis_demo.REPO_DIR / "schemas" / "receipt-predicate-v1.json")],
                label="external schema validation",
                cwd=aegis_demo.REPO_DIR,
                timeout=SUBPROCESS_TIMEOUT,
            )
        finally:
            try:
                instance_path.unlink()
            except FileNotFoundError:
                pass
        return validator_name

    def build_phase_summary(
        self,
        *,
        spec: PhaseSpec,
        result: dict[str, object],
        receipt_doc: dict[str, object],
        verify_output: str,
        schema_validator: str,
        elapsed_seconds: float,
    ) -> dict[str, object]:
        statement = receipt_doc["statement"]
        predicate = statement["predicate"]
        runtime_network = predicate["runtime"]["network"]
        blocked = runtime_network["blocked_egress"]
        broker_summary = predicate.get("broker_summary", {})
        divergence = predicate.get("divergence", {})
        verify_summary = aegis_demo.parse_summary(verify_output)
        exit_code = coerce_int(result.get("exit_code"), default=coerce_int(verify_summary.get("exit_code"), default=0))
        return {
            "phase": spec.name,
            "result": spec.result_label,
            "execution_id": str(result.get("execution_id", "")),
            "proof_dir": str(result.get("proof_dir", "")),
            "receipt_path": str(result.get("receipt_path", "")),
            "receipt_public_key_path": str(result.get("receipt_public_key_path", "")),
            "exit_code": exit_code,
            "exit_reason": str(result.get("exit_reason", "")),
            "duration_ms": coerce_int(result.get("duration_ms"), default=0),
            "stdout": str(result.get("stdout", "")),
            "verify_output": verify_output,
            "verify_summary": verify_summary,
            "schema_validator": schema_validator,
            "schema_validation": "valid",
            "result_class": str(predicate.get("result_class", "")),
            "outcome_reason": str(predicate.get("outcome", {}).get("Reason", "")),
            "execution_status": str(verify_summary.get("execution_status", "")),
            "signer_key_id": str(predicate.get("signer_key_id", "")),
            "divergence_verdict": str(divergence.get("verdict", "")),
            "triggered_rules": list(divergence.get("triggered_rule_ids", []) or []),
            "blocked_egress": blocked,
            "blocked_egress_kinds": blocked_kinds(blocked),
            "broker_summary": broker_summary,
            "broker_allowed_count": coerce_int(broker_summary.get("allowed_count"), default=0),
            "broker_request_count": coerce_int(broker_summary.get("request_count"), default=0),
            "broker_denied_count": coerce_int(broker_summary.get("denied_count"), default=0),
            "broker_domains_allowed": list(broker_summary.get("domains_allowed", []) or []),
            "governed_actions": governed_actions_from_summary(verify_summary),
            "elapsed_seconds": round(elapsed_seconds, 3),
        }

    def print_phase_summary(self, summary: dict[str, object]) -> None:
        print(f"phase={summary['phase']}")
        print(f"execution_id={summary['execution_id']}")
        print(f"proof_dir={summary['proof_dir']}")
        print(f"result={summary['result']}")
        print(f"exit_reason={summary['exit_reason']}")
        print(f"receipt_outcome={summary['result_class']}")
        if summary["phase"] == "adversarial":
            blocked = summary["blocked_egress"]
            print("blocked_egress_kinds=" + ",".join(summary["blocked_egress_kinds"]))
            print(f"blocked_egress_total={blocked['total_count']} unique={blocked['unique_target_count']}")
            print("triggered_rules=" + (",".join(summary["triggered_rules"]) or "none"))
        else:
            print(f"broker_allowed_count={summary['broker_allowed_count']}")
            print("broker_domains_allowed=" + (",".join(summary["broker_domains_allowed"]) or "none"))
        print("verification=" + str(summary["verify_summary"].get("verification", "unknown")))

    def assert_phase_success(self, summary: dict[str, object]) -> None:
        self.assert_common_phase_requirements(summary)
        if summary["phase"] == "adversarial":
            self.assert_adversarial_phase(summary)
            return
        if summary["phase"] == "brokered":
            self.assert_brokered_phase(summary)
            return
        raise DemoFailure(f"unknown phase {summary['phase']!r}")

    def assert_common_phase_requirements(self, summary: dict[str, object]) -> None:
        verify_summary = summary["verify_summary"]
        if verify_summary.get("verification") != "verified":
            raise DemoFailure(f"{summary['phase']}: offline receipt verification failed")
        if str(summary["signer_key_id"]).strip() == "":
            raise DemoFailure(f"{summary['phase']}: receipt signer_key_id is missing")

    def assert_adversarial_phase(self, summary: dict[str, object]) -> None:
        blocked = summary["blocked_egress"]
        sample = {entry["target"]: entry["kind"] for entry in blocked["sample"]}
        verify_summary = summary["verify_summary"]
        governed_actions = summary["governed_actions"]

        if summary["exit_reason"] != "divergence_terminated":
            raise DemoFailure(f"adversarial: expected exit_reason=divergence_terminated, got {summary['exit_reason']!r}")
        if summary["exit_code"] != 137:
            raise DemoFailure(f"adversarial: expected exit_code=137, got {summary['exit_code']}")
        if summary["execution_status"] != "terminated_on_divergence":
            raise DemoFailure(
                f"adversarial: expected execution_status=terminated_on_divergence, got {summary['execution_status']!r}"
            )
        if summary["result_class"] != "denied":
            raise DemoFailure(f"adversarial: expected result_class=denied, got {summary['result_class']!r}")
        if summary["outcome_reason"] != "divergence_terminated":
            raise DemoFailure(
                f"adversarial: expected outcome_reason=divergence_terminated, got {summary['outcome_reason']!r}"
            )
        if summary["divergence_verdict"] != "kill_candidate":
            raise DemoFailure(
                f"adversarial: expected divergence_verdict=kill_candidate, got {summary['divergence_verdict']!r}"
            )
        if set(summary["triggered_rules"]) != {"network.denied_repeated"}:
            raise DemoFailure(
                "adversarial: expected triggered_rules to be exactly network.denied_repeated, "
                + f"got {summary['triggered_rules']}"
            )
        if coerce_int(blocked["total_count"], default=0) < 3:
            raise DemoFailure(f"adversarial: expected blocked_egress.total_count >= 3, got {blocked['total_count']}")
        if coerce_int(blocked["unique_target_count"], default=0) < 3:
            raise DemoFailure(
                "adversarial: expected blocked_egress.unique_target_count >= 3, "
                + f"got {blocked['unique_target_count']}"
            )
        if set(summary["blocked_egress_kinds"]) != EXPECTED_BLOCKED_KINDS:
            raise DemoFailure(
                "adversarial: expected blocked_egress kinds "
                + f"{sorted(EXPECTED_BLOCKED_KINDS)}, got {summary['blocked_egress_kinds']}"
            )
        for target, kind in EXPECTED_BLOCKED_TARGETS.items():
            if sample.get(target) != kind:
                raise DemoFailure(f"adversarial: missing blocked sample entry {target} kind={kind}; sample={blocked['sample']}")
        if verify_summary.get("denial_marker") != "direct_egress_denied":
            raise DemoFailure(
                "adversarial: expected denial_marker=direct_egress_denied, "
                + f"got {verify_summary.get('denial_marker', '')!r}"
            )
        if len(governed_actions) < 2:
            raise DemoFailure(
                f"adversarial: expected governed-action deny evidence for both direct connects, got {governed_actions}"
            )
        if not any("decision=deny" in item and "target=tcp://1.1.1.1:443" in item for item in governed_actions):
            raise DemoFailure(f"adversarial: missing governed deny evidence for tcp://1.1.1.1:443; got {governed_actions}")
        if not any("decision=deny" in item and "target=tcp://10.0.0.5:443" in item for item in governed_actions):
            raise DemoFailure(f"adversarial: missing governed deny evidence for tcp://10.0.0.5:443; got {governed_actions}")

    def assert_brokered_phase(self, summary: dict[str, object]) -> None:
        blocked = summary["blocked_egress"]
        governed_actions = summary["governed_actions"]
        verify_summary = summary["verify_summary"]

        if summary["exit_reason"] != "completed":
            raise DemoFailure(f"brokered: expected exit_reason=completed, got {summary['exit_reason']!r}")
        if summary["exit_code"] != 0:
            raise DemoFailure(f"brokered: expected exit_code=0, got {summary['exit_code']}")
        if summary["execution_status"] != "completed":
            raise DemoFailure(f"brokered: expected execution_status=completed, got {summary['execution_status']!r}")
        if summary["result_class"] != "completed":
            raise DemoFailure(f"brokered: expected result_class=completed, got {summary['result_class']!r}")
        if summary["outcome_reason"] != "completed":
            raise DemoFailure(f"brokered: expected outcome_reason=completed, got {summary['outcome_reason']!r}")
        if summary["divergence_verdict"] != "allow":
            raise DemoFailure(f"brokered: expected divergence_verdict=allow, got {summary['divergence_verdict']!r}")
        if summary["triggered_rules"]:
            raise DemoFailure(f"brokered: expected no triggered rules, got {summary['triggered_rules']}")
        if summary["broker_allowed_count"] != 1:
            raise DemoFailure(
                f"brokered: expected broker_summary.allowed_count=1, got {summary['broker_allowed_count']}"
            )
        if summary["broker_request_count"] != 1:
            raise DemoFailure(
                f"brokered: expected broker_summary.request_count=1, got {summary['broker_request_count']}"
            )
        if summary["broker_denied_count"] != 0:
            raise DemoFailure(
                f"brokered: expected broker_summary.denied_count=0, got {summary['broker_denied_count']}"
            )
        if EXPECTED_BROKER_DOMAIN not in summary["broker_domains_allowed"]:
            raise DemoFailure(
                "brokered: expected broker_summary.domains_allowed to contain api.github.com, "
                + f"got {summary['broker_domains_allowed']}"
            )
        if coerce_int(blocked["total_count"], default=0) != 0 or coerce_int(blocked["unique_target_count"], default=0) != 0:
            raise DemoFailure(f"brokered: expected blocked_egress counts to stay zero, got {blocked}")
        if len(governed_actions) != 1:
            raise DemoFailure(f"brokered: expected one governed allow action, got {governed_actions}")
        allow_entry = governed_actions[0]
        expected_bits = ["decision=allow", "used=true", "brokered=true", f"target={EXPECTED_BROKER_URL}"]
        missing = [bit for bit in expected_bits if bit not in allow_entry]
        if missing:
            raise DemoFailure(f"brokered: governed allow evidence missing {missing}; entry={allow_entry}")
        if verify_summary.get("broker_allowed_count") != "1":
            raise DemoFailure(
                f"brokered: expected verify summary broker_allowed_count=1, got {verify_summary.get('broker_allowed_count', '')!r}"
            )

    def build_run_summary(self, *, elapsed_seconds: float) -> dict[str, object]:
        return {
            "status": "pass",
            "summary_path": str(self.summary_path),
            "started_runtime": self.started_runtime,
            "reused_runtime": self.reused_runtime,
            "policy_path": str(POLICY_PATH),
            "policy_sha256": self._policy_hash,
            "phase_count": len(self._phase_summaries),
            "phases": self._phase_summaries,
            "security_defaults_weakened": False,
            "elapsed_seconds": round(elapsed_seconds, 3),
        }

    def build_failure_summary(self, *, error: str, elapsed_seconds: float) -> dict[str, object]:
        return {
            "status": "fail",
            "summary_path": str(self.summary_path),
            "started_runtime": self.started_runtime,
            "reused_runtime": self.reused_runtime,
            "policy_path": str(POLICY_PATH),
            "policy_sha256": self._policy_hash,
            "phase_count": len(self._phase_summaries),
            "phases": self._phase_summaries,
            "security_defaults_weakened": False,
            "error": error,
            "elapsed_seconds": round(elapsed_seconds, 3),
        }


def build_policy_text() -> str:
    return """allowed_languages: [python, bash, node]
max_code_bytes: 65536
max_output_bytes: 65536
default_timeout_ms: 10000
max_timeout_ms: 10000
network:
  mode: egress_allowlist
  allowlist:
    fqdns:
      - api.github.com
    cidrs: []
resources:
  memory_max_mb: 128
  cpu_percent: 50
  pids_max: 100
  timeout_ms: 10000
"""


def build_phase_specs() -> list[PhaseSpec]:
    return [
        PhaseSpec(name="adversarial", result_label="terminated_as_expected", code=build_adversarial_guest_code()),
        PhaseSpec(name="brokered", result_label="completed", code=build_brokered_guest_code()),
    ]


def build_intent(execution_id: str) -> dict[str, object]:
    intent = aegis_demo.base_intent(
        execution_id=execution_id,
        language="python",
        allow_network=True,
        allowed_ips=[],
        allowed_domains=[],
        allowed_binaries=["python3"],
        allow_shell=False,
        allowed_delegations=[],
        broker_domains=[EXPECTED_BROKER_DOMAIN],
        task_class="demo_egress_allowlist",
        declared_purpose="Prove named-allow outbound enforcement with forensic receipt evidence",
    )
    resource_scope = intent["resource_scope"]
    resource_scope["max_distinct_files"] = 256
    for path in INTENT_EXTRA_READ_PATHS:
        if path not in resource_scope["read_paths"]:
            resource_scope["read_paths"].append(path)
    network_scope = intent["network_scope"]
    del network_scope["allowed_domains"]
    del network_scope["allowed_ips"]
    network_scope["max_dns_queries"] = 2
    network_scope["max_outbound_conns"] = 128
    return intent


def build_adversarial_guest_code() -> str:
    return """import socket


def emit(label, message):
    print(f"{label} {message}", flush=True)


def beat_connect(label, host, port):
    sock = socket.socket()
    sock.settimeout(2)
    try:
        rc = sock.connect_ex((host, port))
        emit(label, f"connect_ex_rc={rc}")
    except Exception as exc:
        emit(label, f"connect_exc={type(exc).__name__}:{exc}")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def beat_dns(label, domain):
    try:
        socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        emit(label, "dns_lookup_unexpected_success")
    except Exception as exc:
        emit(label, f"dns_exc={type(exc).__name__}:{exc}")


beat_connect("beat1", "1.1.1.1", 443)
beat_dns("beat2", "evil-attacker.example.com")
beat_connect("beat3", "10.0.0.5", 443)
"""


def build_brokered_guest_code() -> str:
    return f"""import http.client


def emit(label, message):
    print(f"{{label}} {{message}}", flush=True)


def beat_broker_https(label, url, host_header):
    conn = None
    try:
        conn = http.client.HTTPConnection("127.0.0.1", 8888, timeout=10)
        conn.request("GET", url, headers={{"Host": host_header, "Connection": "close"}})
        response = conn.getresponse()
        body = response.read().decode("utf-8", "replace").strip()
        preview = body.splitlines()[0] if body else ""
        emit(label, f"status={{response.status}} body_preview={{preview[:120]}}")
    except Exception as exc:
        emit(label, f"broker_exc={{type(exc).__name__}}:{{exc}}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


beat_broker_https("beat4", "{EXPECTED_BROKER_URL}", "{EXPECTED_BROKER_DOMAIN}")
"""


def start_runtime_with_policy(policy_path: Path, policy_hash: str) -> aegis_demo.DemoState:
    aegis_demo.ensure_prerequisites()
    aegis_demo.require_file(policy_path, "egress allowlist demo policy")
    aegis_demo.PROOF_ROOT.mkdir(parents=True, exist_ok=True)
    db_port = aegis_demo.find_free_port()
    postgres_url = f"postgresql://{aegis_demo.DEFAULT_DB_USER}@127.0.0.1:{db_port}/{aegis_demo.DEFAULT_DB_NAME}?sslmode=disable"

    go_bin = aegis_demo.resolve_go_bin()
    firecracker = aegis_demo.resolve_firecracker()
    aegis_demo.init_local_postgres(db_port)
    aegis_demo.apply_schema(db_port)
    aegis_demo.run_setup(go_bin, postgres_url)
    aegis_demo.require_file(aegis_demo.KERNEL_PATH, "kernel image")
    aegis_demo.require_file(aegis_demo.ROOTFS_PATH, "rootfs image")
    aegis_demo.require_file(aegis_demo.ORCH_BIN, "repo-local orchestrator binary")
    seed = aegis_demo.require_file(aegis_demo.REPO_DIR / ".aegis" / "receipt_signing_seed.b64", "receipt signing seed").read_text(encoding="utf-8").strip()

    env = os.environ.copy()
    env.update(
        {
            "AEGIS_HTTP_ADDR": aegis_demo.DEFAULT_ADDR,
            "AEGIS_FIRECRACKER_BIN": firecracker,
            "AEGIS_ROOTFS_PATH": str(aegis_demo.ROOTFS_PATH),
            "AEGIS_PROOF_ROOT": str(aegis_demo.PROOF_ROOT),
            "AEGIS_UI_DIR": str(aegis_demo.REPO_DIR / "ui"),
            "AEGIS_RECEIPT_SIGNING_MODE": "strict",
            "AEGIS_RECEIPT_SIGNING_SEED_B64": seed,
        }
    )
    if os.path.isabs(firecracker):
        env["PATH"] = str(Path(firecracker).parent) + os.pathsep + env.get("PATH", "")

    log_handle = aegis_demo.RUNTIME_LOG.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [
            str(aegis_demo.ORCH_BIN),
            "--db",
            postgres_url,
            "--policy",
            str(policy_path),
            "--assets-dir",
            str(aegis_demo.ASSETS_DIR),
            "--rootfs-path",
            str(aegis_demo.ROOTFS_PATH),
            "--addr",
            aegis_demo.DEFAULT_ADDR,
        ],
        cwd=aegis_demo.REPO_DIR,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    log_handle.close()
    try:
        aegis_demo.wait_for_health(aegis_demo.DEFAULT_API_URL, timeout_seconds=60)
    except Exception:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        raise

    state = aegis_demo.DemoState(
        api_url=aegis_demo.DEFAULT_API_URL,
        addr=aegis_demo.DEFAULT_ADDR,
        runtime_pid=proc.pid,
        runtime_log=str(aegis_demo.RUNTIME_LOG),
        postgres_data_dir=str(aegis_demo.POSTGRES_DATA),
        postgres_log=str(aegis_demo.POSTGRES_LOG),
        postgres_port=db_port,
        postgres_user=aegis_demo.DEFAULT_DB_USER,
        postgres_db=aegis_demo.DEFAULT_DB_NAME,
        postgres_url=postgres_url,
        proof_root=str(aegis_demo.PROOF_ROOT),
        broker_binding="none",
    )
    aegis_demo.save_state(state)
    MARKER_PATH.write_text(
        json.dumps(
            {
                "policy_path": str(policy_path),
                "policy_sha256": policy_hash,
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return state


def blocked_kinds(blocked: dict[str, object]) -> list[str]:
    present = {str(entry.get("kind", "")) for entry in blocked.get("sample", []) if str(entry.get("kind", "")).strip()}
    return [kind for kind in EXPECTED_BLOCKED_KIND_ORDER if kind in present]


def coerce_int(value: object, *, default: int) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def governed_actions_from_summary(verify_summary: dict[str, str]) -> list[str]:
    actions: list[str] = []
    index = 1
    while True:
        key = f"governed_action_{index}"
        if key not in verify_summary:
            return actions
        actions.append(str(verify_summary[key]))
        index += 1


def load_marker() -> dict[str, object] | None:
    if not MARKER_PATH.exists():
        return None
    return json.loads(MARKER_PATH.read_text(encoding="utf-8"))


def remove_marker() -> None:
    for path in (MARKER_PATH, POLICY_PATH):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def http_json(base_url: str, method: str, path: str, payload: dict[str, object] | None = None, *, expected_status: int | None = None) -> tuple[int, dict[str, object]]:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=SUBPROCESS_TIMEOUT) as response:
            status = response.getcode()
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read().decode("utf-8")
    parsed = json.loads(body) if body else {}
    if expected_status is not None and status != expected_status:
        raise DemoFailure(f"{method} {path} returned {status}, want {expected_status}: {parsed}")
    return status, parsed


def run_command(
    command: list[str],
    *,
    label: str,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = SUBPROCESS_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise DemoFailure(f"{label} timed out after {timeout}s: {' '.join(command)}") from exc
    if completed.returncode != 0:
        raise DemoFailure(
            f"{label} failed:\ncommand={' '.join(command)}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def load_signed_receipt(receipt_path: str) -> dict[str, object]:
    path = Path(receipt_path)
    if not path.exists():
        raise DemoFailure(f"receipt file missing at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def allocate_summary_path() -> Path:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    candidate = OUTPUT_ROOT / f"run_{stamp}.json"
    if not candidate.exists():
        return candidate
    suffix = 1
    while True:
        candidate = OUTPUT_ROOT / f"run_{stamp}_{suffix}.json"
        if not candidate.exists():
            return candidate
        suffix += 1


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def print_banner(summary_path: Path) -> None:
    print("Aegis egress_allowlist demo")
    print("watch_for=phase adversarial terminates on repeated denied egress; phase brokered completes via api.github.com; both receipts verify offline")
    print(f"summary_json={summary_path}")


def main() -> int:
    return Runner().run()


if __name__ == "__main__":
    sys.exit(main())
