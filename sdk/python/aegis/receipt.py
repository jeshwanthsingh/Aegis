from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .verifier import ReceiptVerification, ReceiptVerifier


@dataclass(slots=True)
class Receipt:
    path: str
    raw: dict[str, Any]
    public_key_path: str | None = None
    summary_path: str | None = None
    verifier: ReceiptVerifier | None = field(default=None, repr=False)

    @classmethod
    def load(
        cls,
        path: str,
        *,
        public_key_path: str | None = None,
        summary_path: str | None = None,
        verifier: ReceiptVerifier | None = None,
    ) -> Receipt:
        raw = json.loads(Path(path).read_text(encoding='utf-8'))
        if public_key_path is None:
            inferred = Path(path).with_name('receipt.pub')
            if inferred.exists():
                public_key_path = str(inferred)
        if summary_path is None:
            inferred_summary = Path(path).with_name('receipt.summary.txt')
            if inferred_summary.exists():
                summary_path = str(inferred_summary)
        return cls(path=path, raw=raw, public_key_path=public_key_path, summary_path=summary_path, verifier=verifier)

    @property
    def proof_dir(self) -> str:
        return str(Path(self.path).parent)

    @property
    def statement(self) -> dict[str, Any]:
        return dict(self.raw.get('statement', {}))

    @property
    def predicate(self) -> dict[str, Any]:
        return dict(self.statement.get('predicate', {}))

    @property
    def execution_id(self) -> str | None:
        return self.predicate.get('execution_id')

    @property
    def verdict(self) -> str | None:
        divergence = self.predicate.get('divergence') or {}
        if isinstance(divergence, dict):
            return divergence.get('verdict')
        return None

    @property
    def signing_mode(self) -> str | None:
        trust = self.predicate.get('trust') or {}
        if isinstance(trust, dict):
            return trust.get('signing_mode')
        return None

    @property
    def key_source(self) -> str | None:
        trust = self.predicate.get('trust') or {}
        if isinstance(trust, dict):
            return trust.get('key_source')
        return None

    @property
    def summary_text(self) -> str | None:
        if not self.summary_path:
            return None
        summary_file = Path(self.summary_path)
        if not summary_file.exists():
            return None
        return summary_file.read_text(encoding='utf-8')

    def verify(self) -> ReceiptVerification:
        verifier = self.verifier or ReceiptVerifier()
        return verifier.verify_receipt(receipt_path=self.path, public_key_path=self.public_key_path)
