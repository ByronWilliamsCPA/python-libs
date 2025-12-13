"""Pytest configuration and fixtures for gemini-image tests."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def sample_image_bytes() -> bytes:
    """Return sample PNG image bytes (1x1 red pixel)."""
    # Minimal valid PNG: 1x1 red pixel
    return base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIA"
        "X8jx0gAAAABJRU5ErkJggg=="
    )


@pytest.fixture
def sample_image_path(tmp_path: Path, sample_image_bytes: bytes) -> Path:
    """Create a temporary sample image file."""
    image_path = tmp_path / "sample.png"
    image_path.write_bytes(sample_image_bytes)
    return image_path


@pytest.fixture
def mock_genai_response(sample_image_bytes: bytes) -> MagicMock:
    """Create a mock Gemini API response with image data."""
    mock_response = MagicMock()

    # Create mock part with inline data
    mock_part = MagicMock()
    mock_part.thought = False
    mock_part.text = None
    mock_part.inline_data = MagicMock()
    mock_part.inline_data.data = sample_image_bytes
    mock_part.inline_data.mime_type = "image/png"

    # Create mock candidate
    mock_candidate = MagicMock()
    mock_candidate.content.parts = [mock_part]

    mock_response.candidates = [mock_candidate]
    return mock_response


@pytest.fixture
def mock_genai_client(mock_genai_response: MagicMock) -> MagicMock:
    """Create a mock Gemini client."""
    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_genai_response
    return mock_client
