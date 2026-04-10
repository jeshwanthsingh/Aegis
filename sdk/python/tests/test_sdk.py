from __future__ import annotations

import json
import os
import threading
import urllib.error
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from aegis import (
    AegisAuthError,
    AegisClient,
    AegisConfigurationError,
    AegisExecutionError,
    AegisValidationError,
    BrokerScope,
    Budgets,
    DoneEvent,
    ExecutionRequest,
    IntentContract,
    NetworkScope,
    ProcessScope,
    ProofEvent,
    ResourceScope,
    StdoutEvent,
)
from aegis.receipt import Receipt
from aegis.result import ExecutionResult
from aegis.verifier import ReceiptVerification, ReceiptVerifier


class SDKServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, responses):
        self.responses = responses
        self.requests = []
        super().__init__(("127.0.0.1", 0), Handler)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.requests.append((self.command, self.path, dict(self.headers), None))
        response = self.server.responses[(self.command, self.path)]
        self.send_response(response[0])
        for key, value in response[1].items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response[2])))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response[2])

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        self.server.requests.append((self.command, self.path, dict(self.headers), body))
        response = self.server.responses[(self.command, self.path)]
        self.send_response(response[0])
        for key, value in response[1].items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response[2])))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response[2])

    def log_message(self, format, *args):
        return


class AegisSDKTests(unittest.TestCase):
    def test_client_env_precedence(self):
        with mock.patch.dict(
            os.environ,
            {
                "AEGIS_BASE_URL": "http://env-base:8080",
                "AEGIS_URL": "http://legacy:8080",
                "AEGIS_API_KEY": "env-key",
            },
            clear=False,
        ):
            client = AegisClient()
            self.assertEqual(client.base_url, "http://env-base:8080")
            self.assertEqual(client.api_key, "env-key")
            self.assertEqual(client.posture.base_url_source, "AEGIS_BASE_URL")
            self.assertEqual(client.posture.api_key_source, "AEGIS_API_KEY")

        with mock.patch.dict(
            os.environ,
            {"AEGIS_BASE_URL": "http://env-base:8080", "AEGIS_API_KEY": "env-key"},
            clear=False,
        ):
            client = AegisClient(base_url="http://explicit:8080", api_key="explicit-key")
            self.assertEqual(client.base_url, "http://explicit:8080")
            self.assertEqual(client.api_key, "explicit-key")
            self.assertEqual(client.posture.base_url_source, "explicit")
            self.assertEqual(client.posture.api_key_source, "explicit")
            self.assertTrue(client.posture.authenticated)

    def test_invalid_client_configuration_raises(self):
        with self.assertRaises(AegisConfigurationError):
            AegisClient(timeout=0)

    def test_health_request_is_unauthed(self):
        server = run_server({
            ("GET", "/v1/health"): (
                200,
                {"Content-Type": "application/json"},
                b'{"status":"ok","worker_slots_available":5,"worker_slots_total":5}',
            ),
        })
        try:
            client = AegisClient(base_url=server_url(server), api_key="token")
            health = client.health()
            self.assertTrue(health.ok)
            method, path, headers, body = server.requests[0]
            self.assertEqual((method, path, body), ("GET", "/v1/health", None))
            self.assertNotIn("Authorization", headers)
        finally:
            stop_server(server)

    def test_run_serializes_request_object_and_auth(self):
        response_body = json.dumps(
            {
                "stdout": "ok\n",
                "stderr": "",
                "exit_code": 0,
                "exit_reason": "completed",
                "duration_ms": 12,
                "execution_id": "exec-1",
                "proof_dir": "/tmp/aegis/proofs/exec-1",
                "receipt_path": "/tmp/aegis/proofs/exec-1/receipt.dsse.json",
                "receipt_public_key_path": "/tmp/aegis/proofs/exec-1/receipt.pub",
                "receipt_summary_path": "/tmp/aegis/proofs/exec-1/receipt.summary.txt",
            }
        ).encode("utf-8")
        server = run_server({
            ("POST", "/v1/execute"): (200, {"Content-Type": "application/json"}, response_body),
        })
        try:
            client = AegisClient(base_url=server_url(server), api_key="token")
            intent = IntentContract(
                version="v1",
                execution_id="11111111-1111-4111-8111-111111111111",
                workflow_id="wf_1",
                task_class="demo",
                declared_purpose="test",
                language="bash",
                resource_scope=ResourceScope("/workspace", ["/workspace"], ["/workspace/out"], [], 3),
                network_scope=NetworkScope(False, [], [], 0, 0),
                process_scope=ProcessScope(["bash"], True, False, 1),
                broker_scope=BrokerScope([], [], [], False),
                budgets=Budgets(10, 128, 100, 4096),
            )
            request = ExecutionRequest(
                language="bash",
                code="echo hi",
                timeout_ms=1000,
                intent=intent,
                profile="default",
            )
            result = client.run(request)
            self.assertTrue(result.ok)
            self.assertEqual(result.stdout, "ok\n")
            method, path, headers, body = server.requests[0]
            self.assertEqual((method, path), ("POST", "/v1/execute"))
            self.assertEqual(headers.get("Authorization"), "Bearer token")
            payload = json.loads(body)
            self.assertEqual(payload["lang"], "bash")
            self.assertEqual(payload["profile"], "default")
            self.assertEqual(payload["intent"]["resource_scope"]["workspace_root"], "/workspace")
        finally:
            stop_server(server)

    def test_run_rejects_mixed_request_and_kwargs(self):
        client = AegisClient(base_url="http://localhost:8080")
        with self.assertRaises(AegisConfigurationError):
            client.run(ExecutionRequest(language="bash", code="echo hi"), language="bash")

    def test_non_2xx_maps_to_sdk_error(self):
        server = run_server({
            ("POST", "/v1/execute"): (
                401,
                {"Content-Type": "application/json"},
                (
                    b'{"error":{"code":"auth_required","message":"Authorization header missing",'
                    b'"details":{"header":"Authorization"}}}'
                ),
            ),
        })
        try:
            client = AegisClient(base_url=server_url(server))
            with self.assertRaises(AegisAuthError):
                client.run(language="bash", code="echo hi")
        finally:
            stop_server(server)

    def test_validation_error_maps_to_validation_exception(self):
        server = run_server({
            ("POST", "/v1/execute"): (
                400,
                {"Content-Type": "application/json"},
                b'{"error":{"code":"invalid_request","message":"invalid request body","details":{}}}',
            ),
        })
        try:
            client = AegisClient(base_url=server_url(server))
            with self.assertRaises(AegisValidationError):
                client.run(language="bash", code="echo hi")
        finally:
            stop_server(server)

    def test_execution_level_failure_inside_200(self):
        server = run_server({
            ("POST", "/v1/execute"): (
                200,
                {"Content-Type": "application/json"},
                b'{"stdout":"","stderr":"","exit_code":0,"exit_reason":"sandbox_error","duration_ms":10,"execution_id":"exec-2","error":"timeout"}',
            ),
        })
        try:
            client = AegisClient(base_url=server_url(server))
            result = client.run(language="bash", code="sleep 1")
            self.assertFalse(result.ok)
            self.assertEqual(result.error, "timeout")
            with self.assertRaises(AegisExecutionError):
                result.raise_for_execution_error()
        finally:
            stop_server(server)

    def test_stream_parsing(self):
        body = (
            b'data: {"type":"stdout","chunk":"hello\\n"}\n\n'
            b'data: {"type":"proof","execution_id":"exec-stream",'
            b'"proof_dir":"/tmp/aegis/proofs/exec-stream",'
            b'"receipt_path":"/tmp/aegis/proofs/exec-stream/receipt.dsse.json",'
            b'"receipt_public_key_path":"/tmp/aegis/proofs/exec-stream/receipt.pub",'
            b'"receipt_summary_path":"/tmp/aegis/proofs/exec-stream/receipt.summary.txt",'
            b'"artifact_count":2,"divergence_verdict":"allow"}\n\n'
            b'data: {"type":"done","exit_code":0,"reason":"completed","duration_ms":12}\n\n'
        )
        server = run_server({
            ("POST", "/v1/execute/stream"): (200, {"Content-Type": "text/event-stream"}, body),
        })
        try:
            client = AegisClient(base_url=server_url(server))
            events = list(client.stream(language="bash", code="echo hi"))
            self.assertIsInstance(events[0], StdoutEvent)
            self.assertIsInstance(events[1], ProofEvent)
            self.assertIsInstance(events[2], DoneEvent)
            self.assertEqual(events[1].proof_bundle.receipt_path, "/tmp/aegis/proofs/exec-stream/receipt.dsse.json")
        finally:
            stop_server(server)

    def test_receipt_wrapper_uses_verifier(self):
        with TemporaryDirectory() as tmp:
            receipt_path = Path(tmp) / "receipt.dsse.json"
            receipt_path.write_text(
                json.dumps(
                    {
                        "statement": {
                            "predicate": {
                                "execution_id": "exec-r",
                                "divergence": {"verdict": "allow"},
                                "trust": {"signing_mode": "strict", "key_source": "configured_seed"},
                            }
                        }
                    }
                )
            )

            class StubVerifier:
                def verify_receipt(self, **kwargs):
                    return ReceiptVerification(
                        True,
                        "verification=verified\nexecution_id=exec-r\n",
                        {"verification": "verified", "execution_id": "exec-r"},
                    )

            receipt = Receipt.load(str(receipt_path), verifier=StubVerifier())
            self.assertEqual(receipt.execution_id, "exec-r")
            self.assertEqual(receipt.verdict, "allow")
            verification = receipt.verify()
            self.assertTrue(verification.verified)

    def test_result_verify_receipt_uses_cached_wrapper(self):
        with TemporaryDirectory() as tmp:
            receipt_path = Path(tmp) / "receipt.dsse.json"
            receipt_path.write_text(json.dumps({"statement": {"predicate": {"execution_id": "exec-r"}}}))

            class StubVerifier:
                def verify_receipt(self, **kwargs):
                    return ReceiptVerification(
                        True,
                        "verification=verified\nexecution_id=exec-r\n",
                        {"verification": "verified", "execution_id": "exec-r"},
                    )

            server = run_server({
                ("POST", "/v1/execute"): (
                    200,
                    {"Content-Type": "application/json"},
                    json.dumps({
                        "stdout": "ok\n",
                        "stderr": "",
                        "exit_code": 0,
                        "exit_reason": "completed",
                        "duration_ms": 1,
                        "execution_id": "exec-r",
                        "receipt_path": str(receipt_path),
                    }).encode("utf-8"),
                ),
            })
            try:
                client = AegisClient(base_url=server_url(server))
                client._verifier = StubVerifier()
                result = client.run(language="bash", code="echo hi")
                verification = result.verify_receipt()
                self.assertTrue(verification.verified)
                self.assertEqual(result.require_receipt().proof_dir, tmp)
            finally:
                stop_server(server)

    def test_receipt_verifier_parses_cli_output(self):
        verifier = ReceiptVerifier(cli_path="/tmp/fake-aegis")
        completed = mock.Mock(
            returncode=0,
            stdout="verification=verified\nexecution_id=exec-1\noutcome=completed exit_code=0\n",
            stderr="",
        )
        with (
            mock.patch.object(
                ReceiptVerifier,
                "resolve_cli_path",
                return_value="/tmp/fake-aegis",
            ),
            mock.patch("subprocess.run", return_value=completed),
        ):
            result = verifier.verify_receipt(receipt_path="/tmp/receipt.dsse.json", public_key_path="/tmp/receipt.pub")
        self.assertTrue(result.verified)
        self.assertEqual(result.fields["execution_id"], "exec-1")
        self.assertEqual(result.fields["exit_code"], "0")

    def test_missing_cli_path_is_configuration_error(self):
        verifier = ReceiptVerifier(cli_path="/tmp/definitely-missing-aegis")
        with (
            mock.patch("pathlib.Path.is_file", return_value=False),
            mock.patch("os.access", return_value=False),
            mock.patch("shutil.which", return_value=None),
        ):
            with self.assertRaises(AegisConfigurationError):
                verifier.resolve_cli_path()

    def test_execution_result_error_and_receipt_branches(self):
        result = ExecutionRequest(language="bash", code="echo hi").to_payload()
        self.assertEqual(result["lang"], "bash")

        parsed = ExecutionResult.from_dict(
            {
                "stdout": "",
                "stderr": "",
                "exit_code": 9,
                "exit_reason": "completed",
                "execution_id": "exec-x",
            }
        )
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.error, "process exited with code 9")
        with self.assertRaises(AegisExecutionError):
            parsed.raise_for_execution_error()

        no_receipt = ExecutionResult.from_dict(
            {"stdout": "", "stderr": "", "exit_code": 0, "execution_id": "exec-y"}
        )
        with self.assertRaisesRegex(Exception, "does not include a readable receipt"):
            no_receipt.require_receipt()

    def test_receipt_load_infers_files_and_summary(self):
        with TemporaryDirectory() as tmp:
            proof_dir = Path(tmp)
            receipt_path = proof_dir / "receipt.dsse.json"
            pub_path = proof_dir / "receipt.pub"
            summary_path = proof_dir / "receipt.summary.txt"
            receipt_path.write_text(json.dumps({"statement": {"predicate": {"execution_id": "exec-r"}}}))
            pub_path.write_text("pub")
            summary_path.write_text("verification=verified\n")

            receipt = Receipt.load(str(receipt_path))
            self.assertEqual(receipt.proof_dir, tmp)
            self.assertEqual(receipt.public_key_path, str(pub_path))
            self.assertEqual(receipt.summary_path, str(summary_path))
            self.assertEqual(receipt.summary_text, "verification=verified\n")
            self.assertIsNone(receipt.verdict)
            self.assertIsNone(receipt.signing_mode)
            self.assertIsNone(receipt.key_source)

    def test_receipt_missing_file_returns_none_from_result(self):
        result = ExecutionResult.from_dict(
            {
                "stdout": "",
                "stderr": "",
                "exit_code": 0,
                "execution_id": "exec-z",
                "receipt_path": "/tmp/definitely-missing.dsse.json",
            }
        )
        self.assertIsNone(result.receipt)

    def test_http_transport_maps_connection_and_decode_failures(self):
        client = AegisClient(base_url="http://localhost:8080")
        transport = client._transport

        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
            with self.assertRaisesRegex(Exception, "offline"):
                transport.request_json("GET", "/v1/health", authenticated=False)

        class StubResponse:
            def __init__(self, body: bytes, content_type: str = "application/json") -> None:
                self._body = body
                self.headers = {"Content-Type": content_type}

            def read(self) -> bytes:
                return self._body

            def close(self) -> None:
                return

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with mock.patch("urllib.request.urlopen", return_value=StubResponse(b"not-json")):
            with self.assertRaisesRegex(Exception, "invalid JSON"):
                transport.request_json("GET", "/v1/health", authenticated=False)

        with mock.patch("urllib.request.urlopen", return_value=StubResponse(b"[]")):
            with self.assertRaisesRegex(Exception, "non-object JSON"):
                transport.request_json("GET", "/v1/health", authenticated=False)

    def test_http_transport_stream_error_paths(self):
        client = AegisClient(base_url="http://localhost:8080")
        transport = client._transport

        class StreamResponse:
            def __init__(self, lines: list[bytes], content_type: str) -> None:
                self._lines = list(lines)
                self.headers = {"Content-Type": content_type}

            def readline(self) -> bytes:
                if not self._lines:
                    return b""
                return self._lines.pop(0)

            def read(self) -> bytes:
                return b"bad body"

            def close(self) -> None:
                return

        with mock.patch("urllib.request.urlopen", return_value=StreamResponse([], "application/json")):
            with self.assertRaisesRegex(Exception, "expected text/event-stream"):
                list(transport.stream_sse("/v1/execute/stream", payload={"lang": "bash"}))

        with mock.patch(
            "urllib.request.urlopen",
            return_value=StreamResponse([b"data: {bad}\n", b"\n"], "text/event-stream"),
        ):
            with self.assertRaisesRegex(Exception, "invalid SSE payload"):
                list(transport.stream_sse("/v1/execute/stream", payload={"lang": "bash"}))

    def test_error_mapping_and_strings(self):
        auth_error = AegisAuthError(401, "auth_required", "missing", {"header": "Authorization"})
        self.assertIn("HTTP 401", str(auth_error))

        mapped = AegisClient(base_url="http://localhost:8080")._transport._map_http_error(
            urllib.error.HTTPError(
                "http://localhost",
                500,
                "boom",
                hdrs=None,
                fp=mock.Mock(read=mock.Mock(return_value=b'{"error":{"code":"server_error","message":"boom"}}')),
            )
        )
        self.assertEqual(mapped.code, "server_error")

    def test_receipt_verifier_argument_and_failure_paths(self):
        verifier = ReceiptVerifier(cli_path="/tmp/fake-aegis")
        with mock.patch.object(ReceiptVerifier, "resolve_cli_path", return_value="/tmp/fake-aegis"):
            with self.assertRaises(AegisConfigurationError):
                verifier.verify_receipt()

            with mock.patch("subprocess.run", side_effect=OSError("no exec")):
                with self.assertRaisesRegex(Exception, "no exec"):
                    verifier.verify_receipt(proof_dir="/tmp/proofs")

            failed = mock.Mock(returncode=1, stdout="", stderr="bad signature")
            with mock.patch("subprocess.run", return_value=failed):
                with self.assertRaisesRegex(Exception, "bad signature"):
                    verifier.verify_receipt(execution_id="exec-1")


def run_server(responses):
    server = SDKServer(responses)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server._thread = thread
    return server


def stop_server(server):
    server.shutdown()
    server.server_close()
    server._thread.join(timeout=2)


def server_url(server):
    return f"http://127.0.0.1:{server.server_port}"
