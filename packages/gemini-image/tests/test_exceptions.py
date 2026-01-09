"""Tests for custom exceptions module."""

from __future__ import annotations

from gemini_image.exceptions import (
    APIError,
    ConfigurationError,
    ContentBlockedError,
    FileOperationError,
    FormatDetectionError,
    GeminiImageError,
    GenerationError,
    RateLimitError,
    ServerError,
    ValidationError,
)


class TestGeminiImageError:
    """Tests for base GeminiImageError."""

    def test_basic_message(self) -> None:
        """Test exception with basic message."""
        exc = GeminiImageError("Test error")
        assert str(exc) == "Test error"
        assert exc.message == "Test error"

    def test_with_details(self) -> None:
        """Test exception with details dictionary."""
        exc = GeminiImageError("Test error", details={"key": "value"})
        assert "key='value'" in str(exc)
        assert exc.details == {"key": "value"}

    def test_inheritance(self) -> None:
        """Test that exception inherits from Exception."""
        exc = GeminiImageError("Test")
        assert isinstance(exc, Exception)


class TestConfigurationError:
    """Tests for ConfigurationError."""

    def test_basic(self) -> None:
        """Test basic configuration error."""
        exc = ConfigurationError("Missing API key")
        assert "Missing API key" in str(exc)
        assert isinstance(exc, GeminiImageError)


class TestAPIError:
    """Tests for APIError and subclasses."""

    def test_api_error_with_status(self) -> None:
        """Test API error with status code."""
        exc = APIError("API failed", status_code=500)
        assert exc.status_code == 500
        assert "status_code=500" in str(exc)

    def test_api_error_with_response(self) -> None:
        """Test API error with response object."""
        exc = APIError("API failed", response={"error": "details"})
        assert exc.response == {"error": "details"}


class TestRateLimitError:
    """Tests for RateLimitError."""

    def test_rate_limit_with_retry_after(self) -> None:
        """Test rate limit error with retry_after."""
        exc = RateLimitError(retry_after=30.0)
        assert exc.retry_after == 30.0
        assert "retry_after=30.0" in str(exc)
        assert isinstance(exc, APIError)

    def test_default_message(self) -> None:
        """Test default error message."""
        exc = RateLimitError()
        assert "rate limit" in str(exc).lower()


class TestServerError:
    """Tests for ServerError."""

    def test_server_error(self) -> None:
        """Test server error."""
        exc = ServerError("Internal error", status_code=503)
        assert exc.status_code == 503
        assert isinstance(exc, APIError)


class TestContentBlockedError:
    """Tests for ContentBlockedError."""

    def test_with_safety_ratings(self) -> None:
        """Test content blocked with safety ratings."""
        ratings = [{"category": "HARM", "probability": "HIGH"}]
        exc = ContentBlockedError(safety_ratings=ratings)
        assert exc.safety_ratings == ratings
        assert isinstance(exc, APIError)

    def test_default_message(self) -> None:
        """Test default error message."""
        exc = ContentBlockedError()
        assert "blocked" in str(exc).lower() or "safety" in str(exc).lower()


class TestValidationError:
    """Tests for ValidationError."""

    def test_with_field_info(self) -> None:
        """Test validation error with field information."""
        exc = ValidationError(
            "Invalid value",
            field="model_key",
            value="invalid",
            valid_options=["flash", "pro"],
        )
        assert exc.field == "model_key"
        assert exc.value == "invalid"
        assert exc.valid_options == ["flash", "pro"]
        assert "field='model_key'" in str(exc)


class TestFormatDetectionError:
    """Tests for FormatDetectionError."""

    def test_with_magic_bytes(self) -> None:
        """Test format detection error with magic bytes."""
        exc = FormatDetectionError(magic_bytes=b"\x00\x01\x02\x03")
        assert exc.magic_bytes == b"\x00\x01\x02\x03"
        # Magic bytes should be hex-encoded in details
        assert "magic_bytes" in exc.details


class TestFileOperationError:
    """Tests for FileOperationError."""

    def test_with_path_and_operation(self) -> None:
        """Test file operation error with path and operation."""
        exc = FileOperationError(
            "Cannot write file",
            path="/tmp/test.png",
            operation="write",
        )
        assert exc.path == "/tmp/test.png"
        assert exc.operation == "write"
        assert "path='/tmp/test.png'" in str(exc)


class TestGenerationError:
    """Tests for GenerationError."""

    def test_with_prompt_and_model(self) -> None:
        """Test generation error with prompt and model."""
        exc = GenerationError(
            "Generation failed",
            prompt="A very long prompt that should be truncated",
            model="pro",
        )
        assert exc.model == "pro"
        assert exc.prompt is not None

    def test_default_message(self) -> None:
        """Test default error message."""
        exc = GenerationError()
        assert "generation" in str(exc).lower() or "failed" in str(exc).lower()
