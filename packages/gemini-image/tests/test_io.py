"""Tests for I/O operations module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gemini_image.exceptions import FileOperationError, FormatDetectionError
from gemini_image.io import (
    detect_image_format,
    get_extension_for_format,
    get_mime_type_for_format,
    load_metadata,
    save_image,
    save_metadata,
    validate_image_file,
)


class TestDetectImageFormat:
    """Tests for detect_image_format function."""

    def test_detect_png(self, sample_image_bytes: bytes) -> None:
        """Test detecting PNG format from magic bytes."""
        assert detect_image_format(sample_image_bytes) == "png"

    def test_detect_jpeg(self) -> None:
        """Test detecting JPEG format from magic bytes."""
        # JPEG magic bytes: FF D8 FF
        jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 100
        assert detect_image_format(jpeg_data) == "jpeg"

    def test_detect_gif87a(self) -> None:
        """Test detecting GIF87a format."""
        gif_data = b"GIF87a" + b"\x00" * 100
        assert detect_image_format(gif_data) == "gif"

    def test_detect_gif89a(self) -> None:
        """Test detecting GIF89a format."""
        gif_data = b"GIF89a" + b"\x00" * 100
        assert detect_image_format(gif_data) == "gif"

    def test_detect_webp(self) -> None:
        """Test detecting WebP format."""
        # WebP magic bytes: RIFF....WEBP
        webp_data = b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 100
        assert detect_image_format(webp_data) == "webp"

    def test_empty_data_raises(self) -> None:
        """Test that empty data raises FormatDetectionError."""
        with pytest.raises(FormatDetectionError, match="Empty image data"):
            detect_image_format(b"")

    def test_unknown_format_raises(self) -> None:
        """Test that unknown format raises FormatDetectionError."""
        with pytest.raises(FormatDetectionError, match="Unknown image format"):
            detect_image_format(b"NOT AN IMAGE FORMAT DATA")


class TestGetExtensionForFormat:
    """Tests for get_extension_for_format function."""

    def test_png_extension(self) -> None:
        """Test PNG format returns .png."""
        assert get_extension_for_format("png") == ".png"

    def test_jpeg_extension(self) -> None:
        """Test JPEG format returns .jpg."""
        assert get_extension_for_format("jpeg") == ".jpg"

    def test_gif_extension(self) -> None:
        """Test GIF format returns .gif."""
        assert get_extension_for_format("gif") == ".gif"

    def test_webp_extension(self) -> None:
        """Test WebP format returns .webp."""
        assert get_extension_for_format("webp") == ".webp"

    def test_unknown_defaults_to_png(self) -> None:
        """Test unknown format defaults to .png."""
        assert get_extension_for_format("unknown") == ".png"


class TestGetMimeTypeForFormat:
    """Tests for get_mime_type_for_format function."""

    def test_png_mime(self) -> None:
        """Test PNG format returns image/png."""
        assert get_mime_type_for_format("png") == "image/png"

    def test_jpeg_mime(self) -> None:
        """Test JPEG format returns image/jpeg."""
        assert get_mime_type_for_format("jpeg") == "image/jpeg"


class TestSaveImage:
    """Tests for save_image function."""

    def test_save_image_basic(
        self, tmp_path: Path, sample_image_bytes: bytes
    ) -> None:
        """Test basic image saving."""
        output_path = tmp_path / "output.png"
        result = save_image(sample_image_bytes, output_path)

        assert result == output_path
        assert output_path.exists()
        assert output_path.read_bytes() == sample_image_bytes

    def test_save_image_corrects_extension(
        self, tmp_path: Path, sample_image_bytes: bytes
    ) -> None:
        """Test that extension is corrected when format doesn't match."""
        # sample_image_bytes is PNG, but we specify .jpg
        output_path = tmp_path / "output.jpg"
        result = save_image(sample_image_bytes, output_path, correct_extension=True)

        # Should be corrected to .png
        assert result.suffix == ".png"
        assert result.exists()

    def test_save_image_no_correction(
        self, tmp_path: Path, sample_image_bytes: bytes
    ) -> None:
        """Test saving without extension correction."""
        output_path = tmp_path / "output.jpg"
        result = save_image(sample_image_bytes, output_path, correct_extension=False)

        # Should keep .jpg even though data is PNG
        assert result.suffix == ".jpg"

    def test_save_image_creates_parents(
        self, tmp_path: Path, sample_image_bytes: bytes
    ) -> None:
        """Test that parent directories are created."""
        output_path = tmp_path / "subdir" / "nested" / "output.png"
        result = save_image(sample_image_bytes, output_path, create_parents=True)

        assert result.exists()
        assert result.parent.exists()


class TestSaveMetadata:
    """Tests for save_metadata function."""

    def test_save_metadata_basic(
        self, tmp_path: Path, sample_image_bytes: bytes
    ) -> None:
        """Test basic metadata saving."""
        image_path = tmp_path / "image.png"
        image_path.write_bytes(sample_image_bytes)

        metadata_path = save_metadata(
            image_path,
            prompt="Test prompt",
            model="pro",
        )

        assert metadata_path.exists()
        assert metadata_path.suffix == ".json"

        with open(metadata_path) as f:
            data = json.load(f)

        assert data["prompt"] == "Test prompt"
        assert data["model"] == "pro"
        assert "created_at" in data

    def test_save_metadata_with_options(
        self, tmp_path: Path, sample_image_bytes: bytes
    ) -> None:
        """Test metadata saving with all options."""
        image_path = tmp_path / "image.png"
        image_path.write_bytes(sample_image_bytes)
        ref_path = tmp_path / "ref.png"

        metadata_path = save_metadata(
            image_path,
            prompt="Test prompt",
            model="pro",
            aspect_ratio="16:9",
            image_size="2K",
            reference_images=[ref_path],
            thought_signature="sig123",
            is_draft=True,
        )

        with open(metadata_path) as f:
            data = json.load(f)

        assert data["aspect_ratio"] == "16:9"
        assert data["image_size"] == "2K"
        assert data["is_draft"] is True
        assert data["thought_signature"] == "sig123"
        assert str(ref_path) in data["reference_images"]


class TestLoadMetadata:
    """Tests for load_metadata function."""

    def test_load_metadata_exists(
        self, tmp_path: Path, sample_image_bytes: bytes
    ) -> None:
        """Test loading existing metadata."""
        image_path = tmp_path / "image.png"
        image_path.write_bytes(sample_image_bytes)

        # Create metadata file
        metadata = {"prompt": "Test", "model": "pro"}
        metadata_path = image_path.with_suffix(".json")
        with open(metadata_path, "w") as f:
            json.dump(metadata, f)

        result = load_metadata(image_path)
        assert result is not None
        assert result["prompt"] == "Test"

    def test_load_metadata_not_exists(self, tmp_path: Path) -> None:
        """Test loading non-existent metadata returns None."""
        image_path = tmp_path / "image.png"
        result = load_metadata(image_path)
        assert result is None


class TestValidateImageFile:
    """Tests for validate_image_file function."""

    def test_validate_png_file(
        self, tmp_path: Path, sample_image_bytes: bytes
    ) -> None:
        """Test validating a PNG file."""
        image_path = tmp_path / "image.png"
        image_path.write_bytes(sample_image_bytes)

        format_str, size = validate_image_file(image_path)
        assert format_str == "png"
        assert size == len(sample_image_bytes)

    def test_validate_missing_file_raises(self, tmp_path: Path) -> None:
        """Test that missing file raises FileOperationError."""
        missing_path = tmp_path / "nonexistent.png"
        with pytest.raises(FileOperationError, match="not found"):
            validate_image_file(missing_path)
