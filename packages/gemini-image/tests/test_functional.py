"""Functional tests with real Gemini API calls.

These tests make real API calls and are skipped by default.
To run them, ensure GEMINI_API_KEY is set and use:

    pytest tests/test_functional.py -v --run-functional

Or set the GEMINI_API_KEY environment variable and use:

    pytest tests/test_functional.py -v -m functional

"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from gemini_image import generate_batch, generate_image, generate_story_sequence
from gemini_image.client import get_api_key
from gemini_image.exceptions import ConfigurationError
from gemini_image.io import detect_image_format, validate_image_file

if TYPE_CHECKING:
    pass

# Check if API key is available
def _has_api_key() -> bool:
    """Check if Gemini API key is configured."""
    try:
        get_api_key()
        return True
    except ConfigurationError:
        return False


# Skip marker for functional tests
requires_api_key = pytest.mark.skipif(
    not _has_api_key(),
    reason="GEMINI_API_KEY not configured - skipping functional tests",
)

# Custom marker for functional tests
functional = pytest.mark.functional


@requires_api_key
@functional
class TestGenerateImageFunctional:
    """Functional tests for generate_image with real API calls."""

    def test_generate_simple_image(self, tmp_path: Path) -> None:
        """Test generating a simple image with default settings."""
        result = generate_image(
            prompt="A simple red square on white background",
            output_dir=tmp_path,
            document=False,
            save_metadata_file=False,
        )

        assert result is not None, "Image generation returned None"
        assert result.exists(), f"Image file not created at {result}"
        assert result.stat().st_size > 0, "Image file is empty"

        # Verify it's a valid image
        image_format, size = validate_image_file(result)
        assert image_format in ("png", "jpeg"), f"Unexpected format: {image_format}"
        assert size > 100, f"Image too small: {size} bytes"

        print(f"\n✓ Generated image: {result} ({size} bytes, {image_format})")

    def test_generate_image_with_aspect_ratio(self, tmp_path: Path) -> None:
        """Test generating an image with specific aspect ratio."""
        result = generate_image(
            prompt="A horizontal landscape with mountains",
            model_key="pro",
            aspect_ratio="16:9",
            output_dir=tmp_path,
            document=False,
            save_metadata_file=False,
        )

        assert result is not None, "Image generation returned None"
        assert result.exists(), f"Image file not created at {result}"

        image_format, size = validate_image_file(result)
        print(f"\n✓ Generated 16:9 image: {result} ({size} bytes, {image_format})")

    def test_generate_draft_image(self, tmp_path: Path) -> None:
        """Test generating a draft image at 1K resolution."""
        result = generate_image(
            prompt="A draft sketch of a house",
            is_draft=True,
            output_dir=tmp_path,
            document=False,
            save_metadata_file=False,
        )

        assert result is not None, "Draft generation returned None"
        assert result.exists(), f"Draft file not created at {result}"
        assert "draft_" in result.name, f"Draft filename should contain 'draft_': {result.name}"

        image_format, size = validate_image_file(result)
        print(f"\n✓ Generated draft: {result} ({size} bytes, {image_format})")

    def test_generate_image_with_metadata(self, tmp_path: Path) -> None:
        """Test that metadata sidecar file is created."""
        result = generate_image(
            prompt="A test image for metadata",
            output_dir=tmp_path,
            document=False,
            save_metadata_file=True,
        )

        assert result is not None, "Image generation returned None"

        # Check for metadata file
        metadata_path = result.with_suffix(".json")
        assert metadata_path.exists(), f"Metadata file not created at {metadata_path}"

        import json

        with open(metadata_path) as f:
            metadata = json.load(f)

        assert "prompt" in metadata, "Metadata missing 'prompt' field"
        assert "model" in metadata, "Metadata missing 'model' field"
        assert "created_at" in metadata, "Metadata missing 'created_at' field"
        assert metadata["prompt"] == "A test image for metadata"

        print(f"\n✓ Generated with metadata: {result}")
        print(f"  Metadata: {metadata_path}")

    def test_generate_image_with_registry(self, tmp_path: Path) -> None:
        """Test that PROMPTS.md registry entry is created."""
        result = generate_image(
            prompt="A test image for registry",
            output_dir=tmp_path,
            document=True,
            save_metadata_file=False,
        )

        assert result is not None, "Image generation returned None"

        # Check for registry file
        registry_path = tmp_path / "PROMPTS.md"
        assert registry_path.exists(), f"Registry file not created at {registry_path}"

        content = registry_path.read_text()
        assert "A test image for registry" in content, "Prompt not found in registry"
        assert result.name in content, "Image filename not found in registry"

        print(f"\n✓ Generated with registry: {result}")
        print(f"  Registry: {registry_path}")


@requires_api_key
@functional
class TestGenerateBatchFunctional:
    """Functional tests for batch generation with real API calls."""

    def test_batch_two_images(self, tmp_path: Path) -> None:
        """Test generating a batch of two images."""
        prompts = [
            {"prompt": "A red circle"},
            {"prompt": "A blue triangle"},
        ]

        results = generate_batch(
            prompts=prompts,
            output_dir=tmp_path,
            document=False,
            show_progress=False,
        )

        assert len(results) == 2, f"Expected 2 results, got {len(results)}"

        successful = [r for r in results if r is not None]
        assert len(successful) == 2, f"Expected 2 successful, got {len(successful)}"

        for i, result in enumerate(results):
            assert result is not None, f"Result {i} is None"
            assert result.exists(), f"Image {i} not created at {result}"
            image_format, size = validate_image_file(result)
            print(f"\n✓ Batch image {i + 1}: {result} ({size} bytes, {image_format})")

    def test_batch_with_different_models(self, tmp_path: Path) -> None:
        """Test batch with different model settings."""
        prompts = [
            {"prompt": "A simple star shape", "model_key": "flash"},
            {"prompt": "A detailed flower", "model_key": "pro", "aspect_ratio": "1:1"},
        ]

        results = generate_batch(
            prompts=prompts,
            output_dir=tmp_path,
            document=False,
            show_progress=False,
        )

        assert len(results) == 2, f"Expected 2 results, got {len(results)}"

        for i, result in enumerate(results):
            if result is not None:
                image_format, size = validate_image_file(result)
                print(f"\n✓ Batch image {i + 1}: {result} ({size} bytes)")


@requires_api_key
@functional
class TestGenerateStorySequenceFunctional:
    """Functional tests for story sequence generation with real API calls."""

    def test_story_sequence_two_parts(self, tmp_path: Path) -> None:
        """Test generating a 2-part story sequence."""
        results = generate_story_sequence(
            base_prompt="A simple shape that transforms: first a circle, then becoming a square",
            num_parts=2,
            output_dir=tmp_path,
            document=False,
        )

        assert len(results) == 2, f"Expected 2 parts, got {len(results)}"

        for i, result in enumerate(results, 1):
            assert result.exists(), f"Part {i} not created at {result}"
            assert f"part{i}" in result.name, f"Part {i} filename missing 'part{i}': {result.name}"
            image_format, size = validate_image_file(result)
            print(f"\n✓ Story part {i}: {result} ({size} bytes, {image_format})")

    def test_story_sequence_resume(self, tmp_path: Path) -> None:
        """Test that story resume skips existing parts."""
        # First, generate part 1
        results1 = generate_story_sequence(
            base_prompt="A growing tree sequence",
            num_parts=1,
            output_prefix=tmp_path / "tree",
            output_dir=tmp_path,
            document=False,
        )

        assert len(results1) == 1, "First generation should produce 1 part"
        part1_path = results1[0]
        part1_size = part1_path.stat().st_size

        # Now try to generate 2 parts with resume - should skip part 1
        results2 = generate_story_sequence(
            base_prompt="A growing tree sequence",
            num_parts=2,
            output_prefix=tmp_path / "tree",
            output_dir=tmp_path,
            resume=True,
            document=False,
        )

        assert len(results2) == 2, f"Expected 2 parts, got {len(results2)}"

        # Part 1 should be the same file (not regenerated)
        assert results2[0] == part1_path, "Part 1 path changed"
        assert results2[0].stat().st_size == part1_size, "Part 1 was regenerated"

        print("\n✓ Story resume worked: Part 1 was reused, Part 2 was generated")


@requires_api_key
@functional
class TestFormatDetectionFunctional:
    """Functional tests for format detection with real generated images."""

    def test_format_detection_matches_extension(self, tmp_path: Path) -> None:
        """Test that detected format matches the saved extension."""
        result = generate_image(
            prompt="A colorful abstract pattern",
            output_dir=tmp_path,
            document=False,
            save_metadata_file=False,
        )

        assert result is not None, "Image generation returned None"

        # Read the image and detect format
        with open(result, "rb") as f:
            data = f.read()

        detected_format = detect_image_format(data)
        expected_ext = ".png" if detected_format == "png" else ".jpg"

        # The extension should match the detected format (after correction)
        actual_ext = result.suffix.lower()
        if detected_format == "jpeg":
            assert actual_ext in (".jpg", ".jpeg"), f"JPEG should have .jpg/.jpeg extension, got {actual_ext}"
        else:
            assert actual_ext == expected_ext, f"Extension mismatch: expected {expected_ext}, got {actual_ext}"

        print(f"\n✓ Format detection: {detected_format} -> {actual_ext}")


# Pytest configuration for custom markers
def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "functional: marks tests as functional (requiring API key)"
    )
