from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class AegisError(Exception):
    """Base SDK error."""


class AegisConnectionError(AegisError):
    """Raised when the SDK cannot reach the Aegis server."""


class AegisConfigurationError(AegisError):
    """Raised when the local SDK configuration is incomplete or invalid."""


@dataclass(slots=True)
class AegisAPIError(AegisError):
    status_code: int
    code: str
    message: str
    details: dict[str, Any] | None = None

    def __str__(self) -> str:
        suffix = f" ({self.code})" if self.code else ""
        return f"HTTP {self.status_code}{suffix}: {self.message}"


class AegisAuthError(AegisAPIError):
    """Authentication or authorization failure."""


class AegisValidationError(AegisAPIError):
    """Request validation failure."""


@dataclass(slots=True)
class AegisExecutionError(AegisError):
    message: str
    execution_id: str | None = None
    exit_code: int | None = None
    exit_reason: str | None = None
    raw_response: dict[str, Any] | None = None

    def __str__(self) -> str:
        parts = [self.message]
        if self.execution_id:
            parts.append(f"execution_id={self.execution_id}")
        if self.exit_code is not None:
            parts.append(f"exit_code={self.exit_code}")
        if self.exit_reason:
            parts.append(f"exit_reason={self.exit_reason}")
        return " ".join(parts)


class AegisVerificationError(AegisError):
    """Receipt verification failed or could not run."""


class AegisStreamError(AegisError):
    """Streaming execution failed."""


def map_api_error(status_code: int, code: str, message: str, details: dict[str, Any] | None = None) -> AegisAPIError:
    if status_code == 401 or code.startswith("auth_"):
        return AegisAuthError(status_code, code, message, details)
    validation_codes = {
        "invalid_request",
        "invalid_intent_contract",
        "invalid_profile",
        "validation_error",
    }
    if status_code == 400 or code in validation_codes:
        return AegisValidationError(status_code, code, message, details)
    return AegisAPIError(status_code, code, message, details)
