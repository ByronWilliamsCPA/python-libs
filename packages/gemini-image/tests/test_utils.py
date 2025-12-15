"""Tests for utility functions."""

# Bandit B101 (assert_used) is expected in test files - pytest uses assert statements

from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from gemini_image.utils import (
    decode_base64_image,
    get_api_key,
    get_file_extension,
    load_image_as_base64,
)

if TYPE_CHECKING:
    from pathlib import Path


class TestGetApiKey:
    """Tests for get_api_key function."""

    def test_get_api_key_from_env(self) -> None:
        """Test getting API key from environment variable."""
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key-123"}):
            assert get_api_key() == "test-key-123"

    def test_get_api_key_from_env_file(self, tmp_path: Path) -> None:
        """Test getting API key from .env file."""
        env_file = tmp_path / ".env"
        env_file.write_text('GEMINI_API_KEY="file-key-456"')

        with patch.dict(os.environ, {}, clear=True):
            # Remove GEMINI_API_KEY if it exists
            os.environ.pop("GEMINI_API_KEY", None)
            assert get_api_key(env_file=env_file) == "file-key-456"

    def test_get_api_key_missing_raises(self) -> None:
        """Test that missing API key raises ValueError."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GEMINI_API_KEY", None)
            with pytest.raises(ValueError, match="GEMINI_API_KEY"):
                get_api_key()


class TestLoadImageAsBase64:
    """Tests for load_image_as_base64 function."""

    def test_load_png_image(self, sample_image_path: Path) -> None:
        """Test loading a PNG image."""
        data, mime_type = load_image_as_base64(sample_image_path)

        assert isinstance(data, str)
        assert mime_type == "image/png"
        # Verify it's valid base64
        decoded = base64.standard_b64decode(data)
        assert len(decoded) > 0

    def test_load_jpeg_image(self, tmp_path: Path, sample_image_bytes: bytes) -> None:
        """Test loading a JPEG image (using PNG bytes, just testing extension)."""
        image_path = tmp_path / "image.jpg"
        image_path.write_bytes(sample_image_bytes)

        _, mime_type = load_image_as_base64(image_path)
        assert mime_type == "image/jpeg"

    def test_load_missing_image_raises(self, tmp_path: Path) -> None:
        """Test that loading missing image raises FileNotFoundError."""
        missing_path = tmp_path / "nonexistent.png"

        with pytest.raises(FileNotFoundError):
            load_image_as_base64(missing_path)


class TestDecodeBase64Image:
    """Tests for decode_base64_image function."""

    def test_decode_valid_base64(self) -> None:
        """Test decoding valid base64 data."""
        original = b"test image data"
        encoded = base64.standard_b64encode(original).decode()

        decoded = decode_base64_image(encoded)
        assert decoded == original


class TestGetFileExtension:
    """Tests for get_file_extension function."""

    def test_png_extension(self) -> None:
        """Test PNG MIME type returns .png."""
        assert get_file_extension("image/png") == ".png"

    def test_jpeg_extension(self) -> None:
        """Test JPEG MIME type returns .jpg."""
        assert get_file_extension("image/jpeg") == ".jpg"

    def test_gif_extension(self) -> None:
        """Test GIF MIME type returns .gif."""
        assert get_file_extension("image/gif") == ".gif"

    def test_webp_extension(self) -> None:
        """Test WebP MIME type returns .webp."""
        assert get_file_extension("image/webp") == ".webp"

    def test_unknown_extension_defaults_to_png(self) -> None:
        """Test unknown MIME type defaults to .png."""
        assert get_file_extension("image/unknown") == ".png"
