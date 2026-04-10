from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .types import ProofBundle


@dataclass(frozen=True, slots=True)
class StreamEvent:
    type: str
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class StdoutEvent(StreamEvent):
    chunk: str


@dataclass(frozen=True, slots=True)
class StderrEvent(StreamEvent):
    chunk: str


@dataclass(frozen=True, slots=True)
class ProofEvent(StreamEvent):
    execution_id: str | None
    proof_bundle: ProofBundle
    artifact_count: int
    divergence_verdict: str | None


@dataclass(frozen=True, slots=True)
class ErrorEvent(StreamEvent):
    error: str


@dataclass(frozen=True, slots=True)
class DoneEvent(StreamEvent):
    exit_code: int
    reason: str | None
    duration_ms: int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and self.reason in {None, "", "completed"}


def parse_stream_event(raw: dict[str, Any]) -> StreamEvent:
    event_type = str(raw.get("type", ""))
    if event_type == "stdout":
        return StdoutEvent(type=event_type, raw=raw, chunk=str(raw.get("chunk", "")))
    if event_type == "stderr":
        return StderrEvent(type=event_type, raw=raw, chunk=str(raw.get("chunk", "")))
    if event_type == "proof":
        return ProofEvent(
            type=event_type,
            raw=raw,
            execution_id=raw.get("execution_id"),
            proof_bundle=ProofBundle(
                proof_dir=raw.get("proof_dir"),
                receipt_path=raw.get("receipt_path"),
                receipt_public_key_path=raw.get("receipt_public_key_path"),
                receipt_summary_path=raw.get("receipt_summary_path"),
            ),
            artifact_count=int(raw.get("artifact_count", 0) or 0),
            divergence_verdict=raw.get("divergence_verdict"),
        )
    if event_type == "error":
        return ErrorEvent(type=event_type, raw=raw, error=str(raw.get("error", "")))
    if event_type == "done":
        return DoneEvent(
            type=event_type,
            raw=raw,
            exit_code=int(raw.get("exit_code", 0) or 0),
            reason=raw.get("reason"),
            duration_ms=int(raw.get("duration_ms", 0) or 0),
        )
    return StreamEvent(type=event_type or "unknown", raw=raw)
