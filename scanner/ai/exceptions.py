from __future__ import annotations

from typing import Any


class AISummarizationError(Exception):
    """Base class for AI summarization and attack-path analysis errors."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "ai_error",
        provider: str | None = None,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.code = code
        self.provider = provider
        self.retryable = retryable
        self.details = details or {}
        super().__init__(self.__str__())

    def __str__(self) -> str:
        parts = [self.message]
        if self.provider:
            parts.append(f"provider={self.provider}")
        parts.append(f"code={self.code}")
        parts.append(f"retryable={self.retryable}")
        return " | ".join(parts)


class AITokenLimitError(AISummarizationError):
    """Raised when LLM token limits are exceeded."""

    def __init__(self, message: str, *, provider: str | None = None) -> None:
        super().__init__(
            message,
            code="ai_token_limit",
            provider=provider,
            retryable=True,
        )


class AITimeoutError(AISummarizationError):
    """Raised when the AI provider times out."""

    def __init__(self, message: str, *, provider: str | None = None) -> None:
        super().__init__(
            message,
            code="ai_timeout",
            provider=provider,
            retryable=True,
        )


class AIProviderError(AISummarizationError):
    """Raised for upstream provider failures."""

    def __init__(
        self,
        message: str,
        *,
        provider: str | None = None,
        retryable: bool = True,
    ) -> None:
        super().__init__(
            message,
            code="ai_provider_error",
            provider=provider,
            retryable=retryable,
        )


class AIInputValidationError(AISummarizationError):
    """Raised when input data is malformed."""

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message,
            code="ai_input_validation",
            retryable=False,
            details=details,
        )


class AIAttackPathError(AISummarizationError):
    """Raised when attack-path generation cannot complete reliably."""

    def __init__(
        self,
        message: str,
        *,
        provider: str | None = None,
        retryable: bool = True,
    ) -> None:
        super().__init__(
            message,
            code="ai_attack_path_error",
            provider=provider,
            retryable=retryable,
        )
