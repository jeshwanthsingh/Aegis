from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import AegisExecutionError, AegisVerificationError
from .receipt import Receipt
from .types import ProofBundle
from .verifier import ReceiptVerification, ReceiptVerifier


@dataclass(slots=True)
class ExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    execution_id: str
    duration_ms: int = 0
    exit_reason: str | None = None
    execution_error: str | None = None
    output_truncated: bool = False
    proof_dir: str | None = None
    receipt_path: str | None = None
    receipt_public_key_path: str | None = None
    receipt_summary_path: str | None = None
    raw_response: dict[str, Any] = field(default_factory=dict)
    _verifier: ReceiptVerifier | None = field(default=None, repr=False, compare=False)
    _receipt_cache: Receipt | None = field(default=None, init=False, repr=False, compare=False)

    @classmethod
    def from_dict(cls, payload: dict[str, Any], verifier: ReceiptVerifier | None = None) -> ExecutionResult:
        return cls(
            stdout=str(payload.get("stdout", "")),
            stderr=str(payload.get("stderr", "")),
            exit_code=int(payload.get("exit_code", 0) or 0),
            execution_id=str(payload.get("execution_id", "")),
            duration_ms=int(payload.get("duration_ms", 0) or 0),
            exit_reason=payload.get("exit_reason"),
            execution_error=payload.get("error"),
            output_truncated=bool(payload.get("output_truncated", False)),
            proof_dir=payload.get("proof_dir"),
            receipt_path=payload.get("receipt_path"),
            receipt_public_key_path=payload.get("receipt_public_key_path"),
            receipt_summary_path=payload.get("receipt_summary_path"),
            raw_response=dict(payload),
            _verifier=verifier,
        )

    @property
    def proof_bundle(self) -> ProofBundle:
        return ProofBundle(
            proof_dir=self.proof_dir,
            receipt_path=self.receipt_path,
            receipt_public_key_path=self.receipt_public_key_path,
            receipt_summary_path=self.receipt_summary_path,
        )

    @property
    def ok(self) -> bool:
        return not self.execution_failed

    @property
    def execution_failed(self) -> bool:
        if self.execution_error:
            return True
        if self.exit_code != 0:
            return True
        return self.exit_reason not in {None, "", "completed"}

    @property
    def error(self) -> str | None:
        if self.execution_error:
            return self.execution_error
        if self.exit_code != 0:
            return f"process exited with code {self.exit_code}"
        if self.exit_reason not in {None, "", "completed"}:
            return self.exit_reason
        return None

    @property
    def receipt(self) -> Receipt | None:
        if self._receipt_cache is not None:
            return self._receipt_cache
        if not self.receipt_path:
            return None
        try:
            self._receipt_cache = Receipt.load(
                self.receipt_path,
                public_key_path=self.receipt_public_key_path,
                summary_path=self.receipt_summary_path,
                verifier=self._verifier,
            )
        except FileNotFoundError:
            return None
        return self._receipt_cache

    def require_receipt(self) -> Receipt:
        receipt = self.receipt
        if receipt is None:
            raise AegisVerificationError("execution result does not include a readable receipt")
        return receipt

    def verify_receipt(self) -> ReceiptVerification:
        return self.require_receipt().verify()

    def raise_for_execution_error(self) -> None:
        if not self.execution_failed:
            return
        raise AegisExecutionError(
            message=self.error or "execution failed",
            execution_id=self.execution_id,
            exit_code=self.exit_code,
            exit_reason=self.exit_reason,
            raw_response=self.raw_response,
        )
