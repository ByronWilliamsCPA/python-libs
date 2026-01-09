"""Tests for image generation functions."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from gemini_image import client as client_module
from gemini_image.exceptions import FileOperationError, ValidationError
from gemini_image.generator import (
    finalize_draft,
    generate_batch,
    generate_image,
    generate_story_sequence,
)

if TYPE_CHECKING:
    from pathlib import Path


class TestGenerateImage:
    """Tests for generate_image function."""

    def test_generate_image_invalid_model_raises(self) -> None:
        """Test that invalid model key raises ValidationError."""
        with pytest.raises(ValidationError, match="Unknown model"):
            generate_image("test prompt", model_key="invalid")  # type: ignore[arg-type]

    def test_generate_image_invalid_aspect_ratio_raises(self) -> None:
        """Test that invalid aspect ratio raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid aspect ratio"):
            generate_image("test prompt", aspect_ratio="invalid")  # type: ignore[arg-type]

    def test_generate_image_new_aspect_ratios_valid(
        self,
        tmp_path: Path,
        mock_genai_response: MagicMock,
    ) -> None:
        """Test that new API aspect ratios are accepted."""
        mock_genai = MagicMock()
        mock_types = MagicMock()

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_genai_response
        mock_genai.Client.return_value = mock_client

        # Test one of the new aspect ratios
        with (
            patch.object(client_module, "_genai", mock_genai),
            patch.object(client_module, "_types", mock_types),
            patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
        ):
            result = generate_image(
                prompt="Test with 21:9 ultra-wide",
                aspect_ratio="21:9",
                output_dir=tmp_path,
                document=False,
            )

        assert result is not None
        assert result.exists()

    def test_generate_image_too_many_references_flash_raises(
        self,
        tmp_path: Path,
        sample_image_path: Path,
    ) -> None:
        """Test that too many reference images for flash model raises ValidationError."""
        # Flash model allows max 3 reference images
        too_many_refs = [sample_image_path] * 4

        with pytest.raises(ValidationError, match="Too many reference images"):
            generate_image(
                "test prompt",
                model_key="flash",
                reference_images=too_many_refs,
            )

    def test_generate_image_too_many_references_pro_raises(
        self,
        tmp_path: Path,
        sample_image_path: Path,
    ) -> None:
        """Test that too many reference images for pro model raises ValidationError."""
        # Pro model allows max 14 reference images
        too_many_refs = [sample_image_path] * 15

        with pytest.raises(ValidationError, match="Too many reference images"):
            generate_image(
                "test prompt",
                model_key="pro",
                reference_images=too_many_refs,
            )

    def test_generate_image_missing_api_key_raises(self) -> None:
        """Test that missing API key raises ConfigurationError."""
        from gemini_image.exceptions import ConfigurationError

        # Mock genai to avoid ImportError
        mock_genai = MagicMock()
        mock_types = MagicMock()

        # Need to mock load_dotenv to prevent it from loading .env file
        with (
            patch.object(client_module, "_genai", mock_genai),
            patch.object(client_module, "_types", mock_types),
            patch("gemini_image.client.load_dotenv"),  # Prevent .env loading
            patch.dict(os.environ, {}, clear=True),
        ):
            with pytest.raises(ConfigurationError, match="GEMINI_API_KEY"):
                generate_image("test prompt")

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
            patch.object(client_module, "_genai", mock_genai),
            patch.object(client_module, "_types", mock_types),
            patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
        ):
            result = generate_image(
                prompt="A test image",
                output_dir=tmp_path,
                verbose=False,
                document=False,  # Disable registry for test
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
            patch.object(client_module, "_genai", mock_genai),
            patch.object(client_module, "_types", mock_types),
            patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
        ):
            result = generate_image(
                prompt="A test draft",
                output_dir=tmp_path,
                is_draft=True,
                document=False,
            )

        assert result is not None
        assert "draft_" in result.name


class TestGenerateStorySequence:
    """Tests for generate_story_sequence function."""

    def test_story_sequence_invalid_parts_raises(self) -> None:
        """Test that num_parts < 1 raises ValidationError."""
        with pytest.raises(ValidationError, match="at least 1"):
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
            patch.object(client_module, "_genai", mock_genai),
            patch.object(client_module, "_types", mock_types),
            patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
        ):
            results = generate_story_sequence(
                base_prompt="A test story",
                num_parts=3,
                output_dir=tmp_path,
                output_prefix=tmp_path / "story",
                document=False,
            )

        assert len(results) == 3
        for i, path in enumerate(results, 1):
            assert path.exists()
            assert f"part{i}" in path.name


class TestFinalizeDraft:
    """Tests for finalize_draft function."""

    def test_finalize_missing_draft_raises(self, tmp_path: Path) -> None:
        """Test that missing draft image raises FileOperationError."""
        missing_path = tmp_path / "nonexistent.png"

        with pytest.raises(FileOperationError):
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
            patch.object(client_module, "_genai", mock_genai),
            patch.object(client_module, "_types", mock_types),
            patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
        ):
            result = finalize_draft(
                draft_path=sample_image_path,
                output_dir=tmp_path,
                document=False,
            )

        assert result is not None
        assert "_final" in result.name


class TestGenerateBatch:
    """Tests for generate_batch function."""

    def test_batch_empty_list_raises(self) -> None:
        """Test that empty prompts list raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            generate_batch([])

    def test_batch_generates_multiple_images(
        self,
        tmp_path: Path,
        mock_genai_response: MagicMock,
    ) -> None:
        """Test that batch generates multiple images."""
        mock_genai = MagicMock()
        mock_types = MagicMock()

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_genai_response
        mock_genai.Client.return_value = mock_client

        prompts = [
            {"prompt": "A sunset over mountains"},
            {"prompt": "A forest in autumn"},
        ]

        with (
            patch.object(client_module, "_genai", mock_genai),
            patch.object(client_module, "_types", mock_types),
            patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
        ):
            results = generate_batch(
                prompts=prompts,
                output_dir=tmp_path,
                document=False,
                show_progress=False,
            )

        assert len(results) == 2
        for result in results:
            assert result is not None
            assert result.exists()

    def test_batch_handles_invalid_prompt(
        self,
        tmp_path: Path,
        mock_genai_response: MagicMock,
    ) -> None:
        """Test that batch handles invalid prompt configs gracefully."""
        mock_genai = MagicMock()
        mock_types = MagicMock()

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_genai_response
        mock_genai.Client.return_value = mock_client

        prompts = [
            {"prompt": "Valid prompt"},
            {"no_prompt_key": "Invalid"},  # Missing 'prompt' key
            {"prompt": "Another valid prompt"},
        ]

        with (
            patch.object(client_module, "_genai", mock_genai),
            patch.object(client_module, "_types", mock_types),
            patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
        ):
            results = generate_batch(
                prompts=prompts,
                output_dir=tmp_path,
                document=False,
                show_progress=False,
            )

        # Should have 3 results: 2 successful, 1 None for invalid
        assert len(results) == 3
        assert results[0] is not None
        assert results[1] is None  # Invalid prompt
        assert results[2] is not None

    def test_batch_resume_skips_existing(
        self,
        tmp_path: Path,
        sample_image_bytes: bytes,
        mock_genai_response: MagicMock,
    ) -> None:
        """Test that batch resume skips existing output files."""
        mock_genai = MagicMock()
        mock_types = MagicMock()

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_genai_response
        mock_genai.Client.return_value = mock_client

        # Create existing file
        existing = tmp_path / "existing.png"
        existing.write_bytes(sample_image_bytes)

        prompts = [
            {"prompt": "New image"},
            {"prompt": "Should skip", "output_path": str(existing)},
        ]

        with (
            patch.object(client_module, "_genai", mock_genai),
            patch.object(client_module, "_types", mock_types),
            patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
        ):
            results = generate_batch(
                prompts=prompts,
                output_dir=tmp_path,
                resume=True,
                document=False,
                show_progress=False,
            )

        assert len(results) == 2
        # The existing file should be returned as-is
        assert results[1] == existing
        # The API should only be called once (for the new image)
        assert mock_client.models.generate_content.call_count == 1
