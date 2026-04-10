from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .errors import AegisConfigurationError, AegisVerificationError


@dataclass(frozen=True, slots=True)
class ReceiptVerification:
    verified: bool
    summary_text: str
    fields: dict[str, str]

    @property
    def execution_id(self) -> str | None:
        return self.fields.get("execution_id")

    @property
    def divergence_verdict(self) -> str | None:
        return self.fields.get("divergence_verdict")

    @property
    def signing_mode(self) -> str | None:
        return self.fields.get("signing_mode")


class ReceiptVerifier:
    def __init__(self, cli_path: str | None = None) -> None:
        self._cli_path = cli_path

    def resolve_cli_path(self) -> str:
        candidates: list[Path] = []
        if self._cli_path:
            candidates.append(Path(self._cli_path))
        env_cli = os.getenv("AEGIS_CLI_BIN")
        if env_cli:
            candidates.append(Path(env_cli))
        cwd = Path.cwd()
        for root in [cwd, *cwd.parents]:
            candidates.append(root / ".aegis/bin/aegis")
        for candidate in candidates:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        which = shutil.which("aegis")
        if which:
            return which
        raise AegisConfigurationError(
            "could not locate the Aegis CLI for receipt verification; set AEGIS_CLI_BIN or install the aegis CLI"
        )

    def verify_receipt(
        self,
        *,
        receipt_path: str | None = None,
        public_key_path: str | None = None,
        proof_dir: str | None = None,
        execution_id: str | None = None,
    ) -> ReceiptVerification:
        cli = self.resolve_cli_path()
        command = [cli, "receipt", "verify"]
        if receipt_path:
            command.extend(["--file", receipt_path])
            if public_key_path:
                command.extend(["--public-key", public_key_path])
        elif proof_dir:
            command.extend(["--proof-dir", proof_dir])
        elif execution_id:
            command.extend(["--execution-id", execution_id])
        else:
            raise AegisConfigurationError("receipt verification requires receipt_path, proof_dir, or execution_id")

        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
        except OSError as exc:
            raise AegisVerificationError(str(exc)) from exc
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or completed.stdout.strip() or "receipt verification failed"
            raise AegisVerificationError(stderr)
        summary_text = completed.stdout
        fields = _parse_summary(summary_text)
        return ReceiptVerification(
            verified=fields.get("verification") == "verified",
            summary_text=summary_text,
            fields=fields,
        )


def _parse_summary(summary_text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for raw_line in summary_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("outcome="):
            for token in line.split():
                if "=" in token:
                    key, value = token.split("=", 1)
                    fields[key] = value
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        fields[key] = value
    return fields
