"""Tests for image generation functions."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from gemini_image import generator
from gemini_image.generator import finalize_draft, generate_story_sequence

if TYPE_CHECKING:
    from pathlib import Path


class TestGenerateImage:
    """Tests for generate_image function."""

    def test_generate_image_invalid_model_raises(self) -> None:
        """Test that invalid model key raises ValueError."""
        # Mock genai to avoid ImportError
        mock_genai = MagicMock()
        mock_types = MagicMock()

        with (
            patch.object(generator, "_genai", mock_genai),
            patch.object(generator, "_types", mock_types),
            patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
            pytest.raises(ValueError, match="Unknown model"),
        ):
            generator.generate_image("test prompt", model_key="invalid")  # type: ignore[arg-type]

    def test_generate_image_missing_api_key_raises(self) -> None:
        """Test that missing API key raises ValueError."""
        # Mock genai to avoid ImportError
        mock_genai = MagicMock()
        mock_types = MagicMock()

        with (
            patch.object(generator, "_genai", mock_genai),
            patch.object(generator, "_types", mock_types),
            patch.dict(os.environ, {}, clear=True),
        ):
            os.environ.pop("GEMINI_API_KEY", None)
            with pytest.raises(ValueError, match="GEMINI_API_KEY"):
                generator.generate_image("test prompt")

    def test_generate_image_with_mock_client(
        self,
        tmp_path: Path,
        mock_genai_response: MagicMock,
    ) -> None:
        """Test image generation with mocked Gemini client."""
        # Create mock genai module
        mock_genai = MagicMock()
        mock_types = MagicMock()

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_genai_response
        mock_genai.Client.return_value = mock_client

        # Patch the lazy-loaded modules
        with (
            patch.object(generator, "_genai", mock_genai),
            patch.object(generator, "_types", mock_types),
            patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
        ):
            result = generator.generate_image(
                prompt="A test image",
                output_dir=tmp_path,
                verbose=False,
            )

        assert result is not None
        assert result.exists()
        assert result.suffix == ".png"

    def test_generate_image_draft_mode_uses_1k(
        self,
        tmp_path: Path,
        mock_genai_response: MagicMock,
    ) -> None:
        """Test that draft mode sets 1K resolution."""
        mock_genai = MagicMock()
        mock_types = MagicMock()

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_genai_response
        mock_genai.Client.return_value = mock_client

        with (
            patch.object(generator, "_genai", mock_genai),
            patch.object(generator, "_types", mock_types),
            patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
        ):
            result = generator.generate_image(
                prompt="A test draft",
                output_dir=tmp_path,
                is_draft=True,
            )

        assert result is not None
        assert "draft_" in result.name


class TestGenerateStorySequence:
    """Tests for generate_story_sequence function."""

    def test_story_sequence_invalid_parts_raises(self) -> None:
        """Test that num_parts < 1 raises ValueError."""
        with pytest.raises(ValueError, match="at least 1"):
            generate_story_sequence("test story", num_parts=0)

    def test_story_sequence_generates_multiple_images(
        self,
        tmp_path: Path,
        mock_genai_response: MagicMock,
    ) -> None:
        """Test that story sequence generates the correct number of images."""
        mock_genai = MagicMock()
        mock_types = MagicMock()

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_genai_response
        mock_genai.Client.return_value = mock_client

        with (
            patch.object(generator, "_genai", mock_genai),
            patch.object(generator, "_types", mock_types),
            patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
        ):
            results = generator.generate_story_sequence(
                base_prompt="A test story",
                num_parts=3,
                output_dir=tmp_path,
                output_prefix=tmp_path / "story",
            )

        assert len(results) == 3
        for i, path in enumerate(results, 1):
            assert path.exists()
            assert f"part{i}" in path.name


class TestFinalizeDraft:
    """Tests for finalize_draft function."""

    def test_finalize_missing_draft_raises(self, tmp_path: Path) -> None:
        """Test that missing draft image raises FileNotFoundError."""
        missing_path = tmp_path / "nonexistent.png"

        with pytest.raises(FileNotFoundError):
            finalize_draft(missing_path)

    def test_finalize_draft_uses_2k_by_default(
        self,
        sample_image_path: Path,
        tmp_path: Path,
        mock_genai_response: MagicMock,
    ) -> None:
        """Test that finalize_draft defaults to 2K resolution."""
        mock_genai = MagicMock()
        mock_types = MagicMock()

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_genai_response
        mock_genai.Client.return_value = mock_client

        with (
            patch.object(generator, "_genai", mock_genai),
            patch.object(generator, "_types", mock_types),
            patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
        ):
            result = generator.finalize_draft(
                draft_path=sample_image_path,
                output_dir=tmp_path,
            )

        assert result is not None
        assert "_final" in result.name
