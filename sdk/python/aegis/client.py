from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from typing import Any

from ._http import HTTPTransport
from .errors import AegisConfigurationError
from .events import StreamEvent, parse_stream_event
from .intent import IntentContract
from .request import ExecutionRequest
from .result import ExecutionResult
from .types import ConnectionPosture, HealthStatus
from .verifier import ReceiptVerification, ReceiptVerifier


class AegisClient:
    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 30.0,
        cli_path: str | None = None,
    ) -> None:
        if timeout <= 0:
            raise AegisConfigurationError("timeout must be greater than zero")
        resolved_base_url, base_url_source = _resolve_base_url(base_url)
        resolved_api_key, api_key_source = _resolve_api_key(api_key)
        self.base_url = resolved_base_url
        self.api_key = resolved_api_key
        self.timeout = timeout
        self.posture = ConnectionPosture(
            base_url=resolved_base_url,
            base_url_source=base_url_source,
            api_key_source=api_key_source,
            api_key_configured=bool(resolved_api_key),
        )
        self._transport = HTTPTransport(
            base_url=resolved_base_url,
            api_key=resolved_api_key,
            timeout=timeout,
        )
        self._verifier = ReceiptVerifier(cli_path=cli_path)

    def health(self) -> HealthStatus:
        payload = self._transport.request_json("GET", "/v1/health", authenticated=False)
        return HealthStatus(
            status=str(payload.get("status", "unknown")),
            worker_slots_available=int(payload.get("worker_slots_available", 0) or 0),
            worker_slots_total=int(payload.get("worker_slots_total", 0) or 0),
        )

    def run(
        self,
        request: ExecutionRequest | None = None,
        *,
        language: str | None = None,
        code: str | None = None,
        timeout_ms: int | None = None,
        intent: IntentContract | Mapping[str, Any] | None = None,
        profile: str | None = None,
        workspace_id: str | None = None,
        execution_id: str | None = None,
    ) -> ExecutionResult:
        execution_request = _coerce_execution_request(
            request=request,
            language=language,
            code=code,
            timeout_ms=timeout_ms,
            intent=intent,
            profile=profile,
            workspace_id=workspace_id,
            execution_id=execution_id,
        )
        response = self._transport.request_json("POST", "/v1/execute", payload=execution_request.to_payload())
        return ExecutionResult.from_dict(response, verifier=self._verifier)

    def run_code(
        self,
        *,
        language: str,
        code: str,
        timeout_ms: int | None = None,
        intent: IntentContract | Mapping[str, Any] | None = None,
        profile: str | None = None,
        workspace_id: str | None = None,
        execution_id: str | None = None,
    ) -> ExecutionResult:
        return self.run(
            language=language,
            code=code,
            timeout_ms=timeout_ms,
            intent=intent,
            profile=profile,
            workspace_id=workspace_id,
            execution_id=execution_id,
        )

    def stream(
        self,
        request: ExecutionRequest | None = None,
        *,
        language: str | None = None,
        code: str | None = None,
        timeout_ms: int | None = None,
        intent: IntentContract | Mapping[str, Any] | None = None,
        profile: str | None = None,
        workspace_id: str | None = None,
        execution_id: str | None = None,
    ) -> Iterator[StreamEvent]:
        execution_request = _coerce_execution_request(
            request=request,
            language=language,
            code=code,
            timeout_ms=timeout_ms,
            intent=intent,
            profile=profile,
            workspace_id=workspace_id,
            execution_id=execution_id,
        )
        for raw_event in self._transport.stream_sse("/v1/execute/stream", payload=execution_request.to_payload()):
            yield parse_stream_event(raw_event)

    def run_stream(
        self,
        *,
        language: str,
        code: str,
        timeout_ms: int | None = None,
        intent: IntentContract | Mapping[str, Any] | None = None,
        profile: str | None = None,
        workspace_id: str | None = None,
        execution_id: str | None = None,
    ) -> Iterator[StreamEvent]:
        return self.stream(
            language=language,
            code=code,
            timeout_ms=timeout_ms,
            intent=intent,
            profile=profile,
            workspace_id=workspace_id,
            execution_id=execution_id,
        )

    def verify_receipt(
        self,
        *,
        receipt_path: str | None = None,
        public_key_path: str | None = None,
        proof_dir: str | None = None,
        execution_id: str | None = None,
    ) -> ReceiptVerification:
        return self._verifier.verify_receipt(
            receipt_path=receipt_path,
            public_key_path=public_key_path,
            proof_dir=proof_dir,
            execution_id=execution_id,
        )


def _coerce_execution_request(
    *,
    request: ExecutionRequest | None,
    language: str | None,
    code: str | None,
    timeout_ms: int | None,
    intent: IntentContract | Mapping[str, Any] | None,
    profile: str | None,
    workspace_id: str | None,
    execution_id: str | None,
) -> ExecutionRequest:
    if request is not None:
        provided_fields = (
            language,
            code,
            timeout_ms,
            intent,
            profile,
            workspace_id,
            execution_id,
        )
        if any(value is not None for value in provided_fields):
            raise AegisConfigurationError(
                "pass either request=ExecutionRequest(...) or keyword execution fields, not both"
            )
        return request
    if not language:
        raise AegisConfigurationError("language is required")
    if code is None:
        raise AegisConfigurationError("code is required")
    return ExecutionRequest(
        language=language,
        code=code,
        timeout_ms=timeout_ms,
        intent=intent,
        profile=profile,
        workspace_id=workspace_id,
        execution_id=execution_id,
    )


def _resolve_base_url(explicit: str | None) -> tuple[str, str]:
    if explicit:
        return explicit.rstrip("/"), "explicit"
    for env_name in ("AEGIS_BASE_URL", "AEGIS_URL"):
        value = os.getenv(env_name)
        if value:
            return value.rstrip("/"), env_name
    return "http://localhost:8080", "default"


def _resolve_api_key(explicit: str | None) -> tuple[str | None, str]:
    if explicit:
        return explicit, "explicit"
    env_value = os.getenv("AEGIS_API_KEY")
    if env_value:
        return env_value, "AEGIS_API_KEY"
    return None, "none"
