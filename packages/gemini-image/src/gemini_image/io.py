"""File I/O operations for Gemini image generation.

This module handles all file operations including:
- Magic byte detection for image format identification
- Safe file saving with extension correction
- Image loading and validation
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from gemini_image.exceptions import FileOperationError, FormatDetectionError

if TYPE_CHECKING:
    from gemini_image.models import AspectRatio, ImageSize, ModelKey

logger = structlog.get_logger(__name__)

# Magic byte signatures for image format detection
# Reference: https://en.wikipedia.org/wiki/List_of_file_signatures
IMAGE_SIGNATURES: dict[bytes, str] = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpeg",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",  # WebP starts with RIFF....WEBP
}

# MIME type to extension mapping
MIME_TO_EXTENSION: dict[str, str] = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
}

# Extension to MIME type mapping
EXTENSION_TO_MIME: dict[str, str] = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
}


def detect_image_format(data: bytes) -> str:
    """Detect image format from magic bytes.

    This function examines the first few bytes of image data to determine
    the actual format, regardless of filename extension. This is critical
    because the Gemini API sometimes returns JPEG data with a PNG extension.

    Args:
        data: Raw image bytes.

    Returns:
        The detected format ('png', 'jpeg', 'gif', or 'webp').

    Raises:
        FormatDetectionError: If the format cannot be detected.

    Example:
        >>> with open("image.png", "rb") as f:
        ...     data = f.read()
        >>> format = detect_image_format(data)
        >>> print(format)  # 'png' or 'jpeg' based on actual content

    """
    if not data:
        raise FormatDetectionError("Empty image data", magic_bytes=b"")

    # Check for PNG (8-byte signature)
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"

    # Check for JPEG (3-byte signature)
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"

    # Check for GIF (6-byte signature)
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"

    # Check for WebP (RIFF....WEBP)
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return "webp"

    # Unknown format
    raise FormatDetectionError(
        "Unknown image format",
        magic_bytes=data[:16],
    )


def get_extension_for_format(image_format: str) -> str:
    """Get the correct file extension for an image format.

    Args:
        image_format: Format string ('png', 'jpeg', 'gif', 'webp').

    Returns:
        File extension including the dot (e.g., '.png').

    """
    extensions = {
        "png": ".png",
        "jpeg": ".jpg",
        "gif": ".gif",
        "webp": ".webp",
    }
    return extensions.get(image_format.lower(), ".png")


def get_mime_type_for_format(image_format: str) -> str:
    """Get the MIME type for an image format.

    Args:
        image_format: Format string ('png', 'jpeg', 'gif', 'webp').

    Returns:
        MIME type string (e.g., 'image/png').

    """
    mime_types = {
        "png": "image/png",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "webp": "image/webp",
    }
    return mime_types.get(image_format.lower(), "image/png")


def save_image(
    data: bytes,
    path: Path,
    *,
    correct_extension: bool = True,
    create_parents: bool = True,
) -> Path:
    """Save image data to a file with optional extension correction.

    This function detects the actual image format from the data and
    optionally corrects the file extension to match. This prevents
    issues where the API returns JPEG data but the user specifies a .png
    extension.

    Args:
        data: Raw image bytes to save.
        path: Target file path.
        correct_extension: If True, corrects the extension based on actual format.
        create_parents: If True, creates parent directories as needed.

    Returns:
        Path where the image was actually saved (may differ from input if
        extension was corrected).

    Raises:
        FormatDetectionError: If the image format cannot be detected.
        FileOperationError: If the file cannot be written.

    Example:
        >>> # User specifies .png but data is actually JPEG
        >>> actual_path = save_image(jpeg_data, Path("image.png"))
        >>> print(actual_path)  # Path("image.jpg")

    """
    # Detect actual format
    actual_format = detect_image_format(data)
    actual_extension = get_extension_for_format(actual_format)

    # Determine final path
    if correct_extension and path.suffix.lower() != actual_extension:
        corrected_path = path.with_suffix(actual_extension)
        logger.info(
            "correcting_file_extension",
            original=str(path),
            corrected=str(corrected_path),
            detected_format=actual_format,
        )
        path = corrected_path

    # Create parent directories
    if create_parents:
        path.parent.mkdir(parents=True, exist_ok=True)

    # Write the file
    try:
        with open(path, "wb") as f:
            f.write(data)
        logger.debug("image_saved", path=str(path), size=len(data))
    except OSError as e:
        raise FileOperationError(
            f"Failed to save image: {e}",
            path=str(path),
            operation="write",
        ) from e

    return path


def save_metadata(
    image_path: Path,
    *,
    prompt: str,
    model: ModelKey,
    aspect_ratio: AspectRatio | None = None,
    image_size: ImageSize | None = None,
    reference_images: list[Path] | None = None,
    thought_signature: str | None = None,
    is_draft: bool = False,
    extra: dict[str, Any] | None = None,
) -> Path:
    """Save metadata sidecar JSON file for a generated image.

    Creates a JSON file alongside the image with generation metadata.
    This enables tracking of generation parameters and supports the
    finalize workflow.

    Args:
        image_path: Path to the generated image.
        prompt: The prompt used for generation.
        model: The model key used.
        aspect_ratio: The aspect ratio used (if any).
        image_size: The image size used (if any).
        reference_images: List of reference image paths used.
        thought_signature: The thought signature from the API (if any).
        is_draft: Whether this is a draft image.
        extra: Additional metadata to include.

    Returns:
        Path to the saved metadata file.

    """
    metadata: dict[str, Any] = {
        "prompt": prompt,
        "model": model,
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
        "is_draft": is_draft,
    }

    if aspect_ratio:
        metadata["aspect_ratio"] = aspect_ratio
    if image_size:
        metadata["image_size"] = image_size
    if reference_images:
        metadata["reference_images"] = [str(p) for p in reference_images]
    if thought_signature:
        metadata["thought_signature"] = thought_signature
    if extra:
        metadata.update(extra)

    # Write metadata file
    metadata_path = image_path.with_suffix(".json")
    try:
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        logger.debug("metadata_saved", path=str(metadata_path))
    except OSError as e:
        raise FileOperationError(
            f"Failed to save metadata: {e}",
            path=str(metadata_path),
            operation="write",
        ) from e

    return metadata_path


def load_metadata(image_path: Path) -> dict[str, Any] | None:
    """Load metadata sidecar JSON file for a generated image.

    Args:
        image_path: Path to the generated image.

    Returns:
        Dictionary with metadata, or None if metadata file doesn't exist.

    Raises:
        FileOperationError: If the metadata file exists but cannot be read.

    """
    metadata_path = image_path.with_suffix(".json")

    if not metadata_path.exists():
        return None

    try:
        with open(metadata_path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise FileOperationError(
            f"Failed to load metadata: {e}",
            path=str(metadata_path),
            operation="read",
        ) from e


def validate_image_file(path: Path) -> tuple[str, int]:
    """Validate that a file is a readable image and return its format.

    Args:
        path: Path to the image file.

    Returns:
        Tuple of (format string, file size in bytes).

    Raises:
        FileOperationError: If the file doesn't exist or can't be read.
        FormatDetectionError: If the file is not a valid image.

    """
    if not path.exists():
        raise FileOperationError(
            f"Image file not found: {path}",
            path=str(path),
            operation="read",
        )

    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise FileOperationError(
            f"Cannot read image file: {e}",
            path=str(path),
            operation="read",
        ) from e

    image_format = detect_image_format(data)
    return image_format, len(data)
