"""Custom exceptions for Gemini image generation.

This module provides a hierarchy of exceptions for handling various error
conditions in the image generation process.
"""

from __future__ import annotations

from typing import Any


class GeminiImageError(Exception):
    """Base exception for all gemini-image errors.

    All custom exceptions in this package inherit from this class,
    allowing users to catch all package-specific errors with a single
    except clause.

    Attributes:
        message: Human-readable error description.
        details: Optional dictionary with additional context.

    """

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        """Initialize the exception.

        Args:
            message: Human-readable error description.
            details: Optional dictionary with additional error context.

        """
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        """Return string representation with details if present."""
        if self.details:
            detail_str = ", ".join(f"{k}={v!r}" for k, v in self.details.items())
            return f"{self.message} ({detail_str})"
        return self.message


class ConfigurationError(GeminiImageError):
    """Raised when there is a configuration problem.

    Examples:
        - Missing API key
        - Invalid model configuration
        - Missing required environment variables

    """


class APIError(GeminiImageError):
    """Base class for API-related errors.

    Attributes:
        status_code: HTTP status code if available.
        response: Raw API response if available.

    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response: Any = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the API error.

        Args:
            message: Human-readable error description.
            status_code: HTTP status code if available.
            response: Raw API response if available.
            details: Optional dictionary with additional error context.

        """
        details = details or {}
        if status_code is not None:
            details["status_code"] = status_code
        super().__init__(message, details=details)
        self.status_code = status_code
        self.response = response


class RateLimitError(APIError):
    """Raised when API rate limit is exceeded.

    This error indicates the request should be retried after a delay.
    The retry logic in GeminiClient handles this automatically.

    """

    def __init__(
        self,
        message: str = "API rate limit exceeded",
        *,
        retry_after: float | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the rate limit error.

        Args:
            message: Human-readable error description.
            retry_after: Suggested wait time in seconds.
            **kwargs: Additional arguments passed to APIError.

        """
        details = kwargs.pop("details", None) or {}
        if retry_after is not None:
            details["retry_after"] = retry_after
        super().__init__(message, details=details, **kwargs)
        self.retry_after = retry_after


class ServerError(APIError):
    """Raised when the API returns a server error (5xx).

    This error indicates a transient failure that may succeed on retry.

    """


class ContentBlockedError(APIError):
    """Raised when content is blocked by safety filters.

    This error indicates the prompt or generated content violated
    content safety policies. Retrying will not help.

    Attributes:
        safety_ratings: Safety ratings from the API if available.

    """

    def __init__(
        self,
        message: str = "Content blocked by safety filters",
        *,
        safety_ratings: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the content blocked error.

        Args:
            message: Human-readable error description.
            safety_ratings: Safety ratings from the API.
            **kwargs: Additional arguments passed to APIError.

        """
        details = kwargs.pop("details", None) or {}
        if safety_ratings:
            details["safety_ratings"] = safety_ratings
        super().__init__(message, details=details, **kwargs)
        self.safety_ratings = safety_ratings


class ValidationError(GeminiImageError):
    """Raised when input validation fails.

    Examples:
        - Invalid model key
        - Invalid aspect ratio
        - Invalid image size

    """

    def __init__(
        self,
        message: str,
        *,
        field: str | None = None,
        value: Any = None,
        valid_options: list[Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the validation error.

        Args:
            message: Human-readable error description.
            field: Name of the field that failed validation.
            value: The invalid value that was provided.
            valid_options: List of valid options if applicable.
            **kwargs: Additional arguments passed to GeminiImageError.

        """
        details = kwargs.pop("details", None) or {}
        if field is not None:
            details["field"] = field
        if value is not None:
            details["value"] = value
        if valid_options is not None:
            details["valid_options"] = valid_options
        super().__init__(message, details=details, **kwargs)
        self.field = field
        self.value = value
        self.valid_options = valid_options


class FormatDetectionError(GeminiImageError):
    """Raised when image format cannot be detected.

    This error indicates the image data does not match any known
    format based on magic bytes.

    """

    def __init__(
        self,
        message: str = "Unable to detect image format",
        *,
        magic_bytes: bytes | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the format detection error.

        Args:
            message: Human-readable error description.
            magic_bytes: First few bytes of the unrecognized data.
            **kwargs: Additional arguments passed to GeminiImageError.

        """
        details = kwargs.pop("details", None) or {}
        if magic_bytes is not None:
            details["magic_bytes"] = magic_bytes.hex()[:32]
        super().__init__(message, details=details, **kwargs)
        self.magic_bytes = magic_bytes


class FileOperationError(GeminiImageError):
    """Raised when a file operation fails.

    Examples:
        - File not found
        - Permission denied
        - Disk full

    """

    def __init__(
        self,
        message: str,
        *,
        path: str | None = None,
        operation: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the file operation error.

        Args:
            message: Human-readable error description.
            path: Path to the file involved.
            operation: Type of operation that failed (read, write, etc.).
            **kwargs: Additional arguments passed to GeminiImageError.

        """
        details = kwargs.pop("details", None) or {}
        if path is not None:
            details["path"] = path
        if operation is not None:
            details["operation"] = operation
        super().__init__(message, details=details, **kwargs)
        self.path = path
        self.operation = operation


class GenerationError(GeminiImageError):
    """Raised when image generation fails.

    This is a general error for failures during the generation process
    that don't fit into more specific categories.

    """

    def __init__(
        self,
        message: str = "Image generation failed",
        *,
        prompt: str | None = None,
        model: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the generation error.

        Args:
            message: Human-readable error description.
            prompt: The prompt that was used (truncated for logging).
            model: The model that was used.
            **kwargs: Additional arguments passed to GeminiImageError.

        """
        details = kwargs.pop("details", None) or {}
        if prompt is not None:
            # Truncate prompt for logging
            details["prompt"] = prompt[:100] + "..." if len(prompt) > 100 else prompt
        if model is not None:
            details["model"] = model
        super().__init__(message, details=details, **kwargs)
        self.prompt = prompt
        self.model = model
