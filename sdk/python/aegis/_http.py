from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

from .errors import AegisAPIError, AegisConnectionError, AegisStreamError, map_api_error


class HTTPTransport:
    def __init__(self, *, base_url: str, api_key: str | None, timeout: float) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def request_json(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        authenticated: bool = True,
    ) -> dict[str, Any]:
        request = self._build_request(method, path, payload=payload, authenticated=authenticated)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise self._map_http_error(exc) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AegisConnectionError(str(exc)) from exc

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise AegisConnectionError(f"server returned invalid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise AegisConnectionError("server returned non-object JSON")
        return payload

    def stream_sse(
        self,
        path: str,
        *,
        payload: dict[str, Any],
        authenticated: bool = True,
    ) -> Iterator[dict[str, Any]]:
        request = self._build_request("POST", path, payload=payload, authenticated=authenticated)
        request.add_header("Accept", "text/event-stream")
        try:
            response = urllib.request.urlopen(request, timeout=self._timeout)
        except urllib.error.HTTPError as exc:
            raise self._map_http_error(exc) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AegisConnectionError(str(exc)) from exc

        content_type = response.headers.get("Content-Type", "")
        if "text/event-stream" not in content_type:
            try:
                body = response.read().decode("utf-8")
            finally:
                response.close()
            raise AegisStreamError(f"expected text/event-stream, got {content_type or 'unknown'}: {body}")

        def iterator() -> Iterator[dict[str, Any]]:
            data_lines: list[str] = []
            try:
                while True:
                    raw = response.readline()
                    if not raw:
                        break
                    line = raw.decode("utf-8").rstrip("\r\n")
                    if not line:
                        if data_lines:
                            payload_text = "\n".join(data_lines)
                            data_lines.clear()
                            try:
                                yield json.loads(payload_text)
                            except json.JSONDecodeError as exc:
                                raise AegisStreamError(f"invalid SSE payload: {exc}") from exc
                        continue
                    if line.startswith(":"):
                        continue
                    if line.startswith("data: "):
                        data_lines.append(line[6:])
                if data_lines:
                    payload_text = "\n".join(data_lines)
                    yield json.loads(payload_text)
            finally:
                response.close()

        return iterator()

    def _build_request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None,
        authenticated: bool,
    ) -> urllib.request.Request:
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if authenticated and self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return urllib.request.Request(self._base_url + path, data=data, headers=headers, method=method)

    def _map_http_error(self, exc: urllib.error.HTTPError) -> AegisAPIError:
        body = exc.read().decode("utf-8", errors="replace")
        code = "http_error"
        message = body.strip() or exc.reason or f"HTTP {exc.code}"
        details = None
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
            error = payload["error"]
            code = str(error.get("code", code))
            message = str(error.get("message", message))
            raw_details = error.get("details")
            details = dict(raw_details) if isinstance(raw_details, dict) else None
        return map_api_error(exc.code, code, message, details)
