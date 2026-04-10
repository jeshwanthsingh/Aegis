from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .intent import IntentContract, coerce_intent_payload


@dataclass(slots=True)
class ExecutionRequest:
    language: str
    code: str
    timeout_ms: int | None = None
    intent: IntentContract | Mapping[str, Any] | None = None
    profile: str | None = None
    workspace_id: str | None = None
    execution_id: str | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"lang": self.language, "code": self.code}
        if self.timeout_ms is not None:
            payload["timeout_ms"] = self.timeout_ms
        if self.profile:
            payload["profile"] = self.profile
        if self.workspace_id:
            payload["workspace_id"] = self.workspace_id
        if self.execution_id:
            payload["execution_id"] = self.execution_id
        intent_payload = coerce_intent_payload(self.intent)
        if intent_payload is not None:
            payload["intent"] = intent_payload
        return payload
