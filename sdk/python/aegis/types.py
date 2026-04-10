from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConnectionPosture:
    base_url: str
    base_url_source: str
    api_key_source: str
    api_key_configured: bool

    @property
    def authenticated(self) -> bool:
        return self.api_key_configured


@dataclass(frozen=True, slots=True)
class HealthStatus:
    status: str
    worker_slots_available: int
    worker_slots_total: int

    @property
    def ok(self) -> bool:
        return self.status == "ok"


@dataclass(frozen=True, slots=True)
class ProofBundle:
    proof_dir: str | None = None
    receipt_path: str | None = None
    receipt_public_key_path: str | None = None
    receipt_summary_path: str | None = None
