from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import aegis_demo


class AegisDemoHelpersTest(unittest.TestCase):
    def test_prepare_demo_artifact_dir_is_deterministic_and_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            original = aegis_demo.ARTIFACTS_ROOT
            try:
                aegis_demo.ARTIFACTS_ROOT = Path(tempdir) / "artifacts"
                first = aegis_demo.prepare_demo_artifact_dir("Demo C: Host Patch Approved", "exec-123")
                second = aegis_demo.prepare_demo_artifact_dir("Demo C: Host Patch Approved", "exec-123")
                self.assertTrue(first.exists())
            finally:
                aegis_demo.ARTIFACTS_ROOT = original
        self.assertEqual(first, second)
        self.assertIn("demo-c-host-patch-approved", str(first))

    def test_inject_approval_token_preserves_slot_length(self) -> None:
        template = f"TOKEN={aegis_demo.TOKEN_SLOT_MARKER!r}\n"
        rendered = aegis_demo.inject_approval_token(template, "ticket-token")
        self.assertEqual(len(rendered), len(template))
        self.assertIn("ticket-token", rendered)
        self.assertNotIn(aegis_demo.TOKEN_SLOT_PREFIX, rendered)

    def test_sanitize_approval_issue_output_removes_token(self) -> None:
        output = "\n".join(
            [
                "status=issued",
                "ticket_id=ticket-1",
                "approval_ticket_token=secret-token",
                "issuer_key_id=ed25519:test",
            ]
        )
        sanitized = aegis_demo.sanitize_approval_issue_output(output)
        self.assertIn("ticket_id=ticket-1", sanitized)
        self.assertNotIn("approval_ticket_token=", sanitized)
        self.assertNotIn("secret-token", sanitized)

    def test_receipt_summary_key_fields_reads_governed_action_fields(self) -> None:
        summary = {
            "result_class": "denied",
            "outcome": "denied",
            "authority_digest": "auth-digest",
            "governed_action_1": "kind=host_repo_apply_patch approval_result=missing host_action_class=repo_apply_patch_v1 repo_label=demo patch_digest=sha256:abcd affected_paths=demo.txt",
            "runtime_policy_escalation_count": "0",
        }
        rendered = aegis_demo.receipt_summary_key_fields(summary)
        self.assertIn("authority_digest=auth-digest", rendered)
        self.assertIn("approval_result=missing", rendered)
        self.assertIn("host_action_class=repo_apply_patch_v1", rendered)
        self.assertIn("repo_label=demo", rendered)

    def test_print_demo_result_emits_required_fields_without_token(self) -> None:
        result = aegis_demo.DemoResult(
            run_output="",
            user_output="DEMO_OK",
            proof_dir="/tmp/aegis-demo/proofs/exec-1",
            show_output="",
            verify_output="",
            summary={
                "execution_id": "exec-1",
                "verification": "verified",
                "result_class": "completed",
                "outcome": "completed",
                "authority_digest": "auth-digest",
                "runtime_policy_termination_reason": "none",
            },
            artifact_dir="/tmp/aegis-demo/artifacts/demo/exec-1",
            status="success",
            verify_command="/home/cellardoor72/aegis/.aegis/bin/aegis receipt verify --proof-dir /tmp/aegis-demo/proofs/exec-1",
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            aegis_demo.print_demo_result("demo_x", result)
        rendered = stdout.getvalue()
        for needle in [
            "demo=demo_x",
            "status=success",
            "execution_id=exec-1",
            "proof_dir=/tmp/aegis-demo/proofs/exec-1",
            "verify_command=/home/cellardoor72/aegis/.aegis/bin/aegis receipt verify --proof-dir /tmp/aegis-demo/proofs/exec-1",
            "receipt_summary_key_fields=result_class=completed outcome=completed authority_digest=auth-digest",
        ]:
            self.assertIn(needle, rendered)
        self.assertNotIn("approval_ticket_token=", rendered)
        self.assertNotIn("secret-token", rendered)

    def test_demo_preflight_reports_missing_prerequisites_deterministically(self) -> None:
        original = aegis_demo.collect_preflight_issues
        try:
            aegis_demo.collect_preflight_issues = lambda: ["zeta missing", "alpha missing"]
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = aegis_demo.demo_preflight()
        finally:
            aegis_demo.collect_preflight_issues = original
        rendered = stdout.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("status=failed", rendered)
        self.assertIn("missing_count=2", rendered)
        self.assertIn("missing_1=alpha missing", rendered)
        self.assertIn("missing_2=zeta missing", rendered)

    def test_ensure_runtime_running_fails_preflight_before_health_check(self) -> None:
        original_collect = aegis_demo.collect_preflight_issues
        original_health = aegis_demo.runtime_health
        try:
            aegis_demo.collect_preflight_issues = lambda: ["missing binary"]
            aegis_demo.runtime_health = lambda _url: True
            with self.assertRaises(aegis_demo.DemoError) as exc:
                aegis_demo.ensure_runtime_running()
        finally:
            aegis_demo.collect_preflight_issues = original_collect
            aegis_demo.runtime_health = original_health
        self.assertIn("demo preflight failed", str(exc.exception))
        self.assertIn("missing binary", str(exc.exception))

    def test_cleanup_legacy_runtime_inputs_removes_staged_token_files(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            original_state = aegis_demo.STATE_DIR
            try:
                aegis_demo.STATE_DIR = Path(tempdir)
                runtime_dir = aegis_demo.STATE_DIR / "runtime-inputs" / "demo" / "exec-1"
                runtime_dir.mkdir(parents=True, exist_ok=True)
                (runtime_dir / "code.py").write_text("token=secret-token\n", encoding="utf-8")
                aegis_demo.cleanup_legacy_runtime_inputs()
            finally:
                aegis_demo.STATE_DIR = original_state
            self.assertFalse(runtime_dir.exists())

    def test_host_patch_approved_uses_in_memory_code_not_runtime_staging(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_root = Path(tempdir)
            artifact_dir = temp_root / "artifacts" / "demo-c" / "exec-123"
            artifact_dir.mkdir(parents=True, exist_ok=True)
            template_path = artifact_dir / "code.template.py"
            template_path.write_text(aegis_demo.host_patch_code_template(patch_text=aegis_demo.demo_repo_patch(), base_revision="base123", ticket_slot=aegis_demo.approval_token_slot()), encoding="utf-8")
            intent_path = artifact_dir / "intent.json"
            intent_path.write_text("{}", encoding="utf-8")
            captured: dict[str, object] = {}
            originals = {
                "ensure_runtime_running": aegis_demo.ensure_runtime_running,
                "ensure_demo_repo_baseline": aegis_demo.ensure_demo_repo_baseline,
                "prepare_demo_artifact_dir": aegis_demo.prepare_demo_artifact_dir,
                "write_patch_artifact": aegis_demo.write_patch_artifact,
                "write_demo_inputs": aegis_demo.write_demo_inputs,
                "preview_demo_execution": aegis_demo.preview_demo_execution,
                "issue_host_patch_approval": aegis_demo.issue_host_patch_approval,
                "run_cli_demo": aegis_demo.run_cli_demo,
                "assert_demo_repo_contents": aegis_demo.assert_demo_repo_contents,
                "print_demo_result": aegis_demo.print_demo_result,
            }
            try:
                aegis_demo.ensure_runtime_running = lambda: None
                aegis_demo.ensure_demo_repo_baseline = lambda: "base123"
                aegis_demo.prepare_demo_artifact_dir = lambda _label, _execution_id: artifact_dir
                aegis_demo.write_patch_artifact = lambda _artifact_dir, _patch_text: artifact_dir / "patch.diff"
                aegis_demo.write_demo_inputs = lambda _artifact_dir, _code, _intent, language: (template_path, intent_path)
                aegis_demo.preview_demo_execution = lambda _code_path, _intent_path, language: {"execution_id": "exec-123", "policy_digest": "policy-123"}
                def fake_issue_host_patch_approval(**_kwargs):
                    (artifact_dir / "approval.summary.txt").write_text("status=issued\n", encoding="utf-8")
                    return {"approval_ticket_token": "secret-token"}
                aegis_demo.issue_host_patch_approval = fake_issue_host_patch_approval
                def fake_run_cli_demo(**kwargs):
                    captured["run_args"] = kwargs["run_args"]
                    return aegis_demo.DemoResult(
                        run_output="",
                        user_output="",
                        proof_dir="/tmp/aegis-demo/proofs/exec-123",
                        show_output="",
                        verify_output="",
                        summary={"execution_id": "exec-123", "verification": "verified", "result_class": "completed", "outcome": "completed", "authority_digest": "auth"},
                        artifact_dir=str(artifact_dir),
                        status="success",
                        verify_command="verify",
                    )
                aegis_demo.run_cli_demo = fake_run_cli_demo
                aegis_demo.assert_demo_repo_contents = lambda *_args, **_kwargs: None
                aegis_demo.print_demo_result = lambda *_args, **_kwargs: None
                code = aegis_demo.demo_host_patch_approved()
            finally:
                for name, value in originals.items():
                    setattr(aegis_demo, name, value)
            self.assertEqual(code, 0)
            run_args = captured["run_args"]
            self.assertIn("--code", run_args)
            self.assertNotIn("--file", run_args)
            self.assertNotIn("secret-token", (artifact_dir / "approval.summary.txt").read_text(encoding="utf-8"))

    def test_broker_http_uses_in_memory_code_not_runtime_staging(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_root = Path(tempdir)
            artifact_dir = temp_root / "artifacts" / "demo-d" / "exec-123"
            artifact_dir.mkdir(parents=True, exist_ok=True)
            captured: dict[str, object] = {}
            originals = {
                "ensure_runtime_running": aegis_demo.ensure_runtime_running,
                "prepare_demo_artifact_dir": aegis_demo.prepare_demo_artifact_dir,
                "write_demo_inputs": aegis_demo.write_demo_inputs,
                "preview_demo_execution": aegis_demo.preview_demo_execution,
                "issue_http_approval": aegis_demo.issue_http_approval,
                "run_cli_demo": aegis_demo.run_cli_demo,
                "print_demo_result": aegis_demo.print_demo_result,
                "ProbeContext": aegis_demo.ProbeContext,
            }
            class FakeProbeServer:
                port = 4321
                observations = [type("Obs", (), {"auth_present": True})()]
            class FakeProbeContext:
                def __enter__(self):
                    return FakeProbeServer()
                def __exit__(self, exc_type, exc, tb):
                    return None
            try:
                aegis_demo.ensure_runtime_running = lambda: None
                aegis_demo.prepare_demo_artifact_dir = lambda _label, _execution_id: artifact_dir
                template_path = artifact_dir / "code.template.py"
                template_path.write_text(aegis_demo.broker_http_code_template(port=4321, ticket_slot=aegis_demo.approval_token_slot()), encoding="utf-8")
                intent_path = artifact_dir / "intent.json"
                intent_path.write_text("{}", encoding="utf-8")
                aegis_demo.write_demo_inputs = lambda _artifact_dir, _code, _intent, language: (template_path, intent_path)
                aegis_demo.preview_demo_execution = lambda _code_path, _intent_path, language: {"execution_id": "exec-123", "policy_digest": "policy-123"}
                def fake_issue_http_approval(**_kwargs):
                    (artifact_dir / "approval.summary.txt").write_text("status=issued\n", encoding="utf-8")
                    return {"approval_ticket_token": "secret-token"}
                aegis_demo.issue_http_approval = fake_issue_http_approval
                def fake_run_cli_demo(**kwargs):
                    captured["run_args"] = kwargs["run_args"]
                    return aegis_demo.DemoResult(
                        run_output="",
                        user_output="",
                        proof_dir="/tmp/aegis-demo/proofs/exec-123",
                        show_output="",
                        verify_output="",
                        summary={"execution_id": "exec-123", "verification": "verified", "result_class": "completed", "outcome": "completed", "authority_digest": "auth", "broker_allowed_count": "1"},
                        artifact_dir=str(artifact_dir),
                        status="success",
                        verify_command="verify",
                    )
                aegis_demo.run_cli_demo = fake_run_cli_demo
                aegis_demo.print_demo_result = lambda *_args, **_kwargs: None
                aegis_demo.ProbeContext = FakeProbeContext
                code = aegis_demo.demo_broker_http()
            finally:
                for name, value in originals.items():
                    setattr(aegis_demo, name, value)
            self.assertEqual(code, 0)
            run_args = captured["run_args"]
            self.assertIn("--code", run_args)
            self.assertNotIn("--file", run_args)
            self.assertNotIn("secret-token", (artifact_dir / "approval.summary.txt").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
