class AISummarizationError(Exception):
    """Base class for AI summarization errors."""


class AITokenLimitError(AISummarizationError):
    """Raised when LLM token limits are exceeded."""


class AITimeoutError(AISummarizationError):
    """Raised when the AI provider times out."""


class AIProviderError(AISummarizationError):
    """Raised for upstream provider failures."""


class AIInputValidationError(AISummarizationError):
    """Raised when input data is malformed."""
