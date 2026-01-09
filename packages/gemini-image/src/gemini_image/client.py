"""Gemini API client with retry logic and error handling.

This module provides a wrapper around the google-genai client with:
- Automatic retry on transient failures (rate limits, server errors)
- Structured logging
- Custom exception mapping
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import structlog
from dotenv import load_dotenv
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from gemini_image.exceptions import (
    APIError,
    ConfigurationError,
    ContentBlockedError,
    RateLimitError,
    ServerError,
)

logger = structlog.get_logger(__name__)

# Lazy import for google.genai
_genai = None
_types = None


def _get_genai() -> tuple[Any, Any]:
    """Lazy import google.genai to avoid import errors when not installed."""
    global _genai, _types  # noqa: PLW0603
    if _genai is None:
        try:
            from google import genai
            from google.genai import types

            _genai = genai
            _types = types
        except ImportError as e:
            msg = (
                "google-genai package not installed. "
                "Install with: pip install google-genai"
            )
            raise ImportError(msg) from e
    return _genai, _types


def get_api_key(env_file: Path | None = None) -> str:
    """Get the Gemini API key from environment or .env file.

    This function uses python-dotenv for robust .env file parsing,
    supporting quoted values, comments, and multiline values.

    Args:
        env_file: Optional path to .env file. If not provided, searches
            for .env in current directory and parent directories.

    Returns:
        The API key string.

    Raises:
        ConfigurationError: If no API key is found.

    """
    # Load .env file if it exists
    if env_file:
        load_dotenv(env_file)
    else:
        # Search for .env in current and parent directories
        load_dotenv()

    api_key = os.environ.get("GEMINI_API_KEY")

    if not api_key:
        raise ConfigurationError(
            "GEMINI_API_KEY environment variable not set",
            details={
                "hint": "Set it with: export GEMINI_API_KEY='your-api-key'",
                "alternative": "Create a .env file with GEMINI_API_KEY=your-key",
            },
        )

    return api_key


# Custom exception for retry logic
class _RetryableError(Exception):
    """Internal marker for retryable errors."""


def _is_retryable_exception(exc: BaseException) -> bool:
    """Check if an exception should trigger a retry."""
    # Check our custom exceptions
    if isinstance(exc, (RateLimitError, ServerError, _RetryableError)):
        return True

    # Check google-genai exceptions
    exc_type = type(exc).__name__
    exc_str = str(exc).lower()

    # Rate limit indicators
    if "429" in exc_str or ("rate" in exc_str and "limit" in exc_str):
        return True

    # Server error indicators
    if any(code in exc_str for code in ["500", "502", "503", "504"]):
        return True

    # Connection errors
    if exc_type in ("ConnectionError", "TimeoutError", "ConnectionResetError"):
        return True

    return False


class GeminiClient:
    """Wrapper around google-genai with retry logic and error handling.

    This client provides:
    - Automatic retry on transient failures (rate limits, server errors)
    - Exponential backoff between retries
    - Structured logging of requests and responses
    - Custom exception mapping for better error handling

    Example:
        >>> client = GeminiClient()
        >>> response = client.generate_content(
        ...     model="gemini-3-pro-image-preview",
        ...     contents=["A beautiful sunset"],
        ...     config=generate_config,
        ... )

    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        max_retries: int = 3,
        min_retry_wait: float = 4.0,
        max_retry_wait: float = 60.0,
    ) -> None:
        """Initialize the Gemini client.

        Args:
            api_key: API key for authentication. If not provided, reads from
                GEMINI_API_KEY environment variable.
            max_retries: Maximum number of retry attempts for transient failures.
            min_retry_wait: Minimum wait time between retries in seconds.
            max_retry_wait: Maximum wait time between retries in seconds.

        Raises:
            ConfigurationError: If no API key is available.
            ImportError: If google-genai is not installed.

        """
        self._api_key = api_key or get_api_key()
        self._max_retries = max_retries
        self._min_retry_wait = min_retry_wait
        self._max_retry_wait = max_retry_wait

        genai, _ = _get_genai()
        self._client = genai.Client(api_key=self._api_key)

        logger.debug(
            "gemini_client_initialized",
            max_retries=max_retries,
        )

    @property
    def client(self) -> Any:
        """Access the underlying google-genai client."""
        return self._client

    def generate_content(
        self,
        *,
        model: str,
        contents: list[Any],
        config: Any,
    ) -> Any:
        """Generate content with automatic retry on transient failures.

        This method wraps the underlying API call with retry logic using
        exponential backoff. It automatically retries on:
        - HTTP 429 (rate limit exceeded)
        - HTTP 5xx (server errors)
        - Connection errors and timeouts

        Args:
            model: Model ID to use for generation.
            contents: List of content parts (text, images).
            config: Generation configuration.

        Returns:
            The API response.

        Raises:
            RateLimitError: If rate limit exceeded after all retries.
            ServerError: If server error persists after all retries.
            ContentBlockedError: If content is blocked by safety filters.
            APIError: For other API errors.

        """
        # Create the retry decorator dynamically to use instance settings
        @retry(
            stop=stop_after_attempt(self._max_retries),
            wait=wait_exponential(
                multiplier=1,
                min=self._min_retry_wait,
                max=self._max_retry_wait,
            ),
            retry=retry_if_exception_type(_RetryableError),
            reraise=True,
        )
        def _generate_with_retry() -> Any:
            try:
                logger.debug(
                    "generating_content",
                    model=model,
                    content_parts=len(contents),
                )

                response = self._client.models.generate_content(
                    model=model,
                    contents=contents,
                    config=config,
                )

                logger.debug(
                    "generation_complete",
                    has_candidates=bool(response.candidates),
                )

                return response

            except Exception as e:
                # Map to our exception types
                mapped_exc = self._map_exception(e)

                # Re-raise retryable exceptions wrapped for tenacity
                if isinstance(mapped_exc, (RateLimitError, ServerError)):
                    logger.warning(
                        "retryable_error",
                        error_type=type(mapped_exc).__name__,
                        message=str(mapped_exc),
                    )
                    raise _RetryableError(str(mapped_exc)) from mapped_exc

                # Non-retryable exceptions
                raise mapped_exc from e

        try:
            return _generate_with_retry()
        except _RetryableError as e:
            # If we exhausted retries, raise the underlying exception
            if e.__cause__:
                raise e.__cause__ from None
            raise APIError(f"Generation failed after retries: {e}") from e

    def _map_exception(self, exc: Exception) -> Exception:
        """Map google-genai exceptions to our exception types."""
        exc_str = str(exc).lower()
        exc_type = type(exc).__name__

        # Check for rate limit
        if "429" in exc_str or ("rate" in exc_str and "limit" in exc_str):
            return RateLimitError(
                f"API rate limit exceeded: {exc}",
                status_code=429,
            )

        # Check for server errors
        for code in ["500", "502", "503", "504"]:
            if code in exc_str:
                return ServerError(
                    f"API server error: {exc}",
                    status_code=int(code),
                )

        # Check for content blocked
        if "blocked" in exc_str or "safety" in exc_str:
            return ContentBlockedError(
                f"Content blocked by safety filters: {exc}",
            )

        # Check for connection errors
        if exc_type in ("ConnectionError", "TimeoutError", "ConnectionResetError"):
            return ServerError(f"Connection error: {exc}")

        # Generic API error
        return APIError(f"API error: {exc}")
