"""Utility functions for Gemini image generation."""

from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def get_api_key(env_file: Path | None = None) -> str:
    """Get the Gemini API key from environment or .env file.

    Args:
        env_file: Optional path to .env file. If not provided, checks
            GEMINI_API_KEY environment variable only.

    Returns:
        The API key string.

    Raises:
        ValueError: If no API key is found.

    """
    api_key = os.environ.get("GEMINI_API_KEY")

    if not api_key and env_file and env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line.startswith("GEMINI_API_KEY="):
                    api_key = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break

    if not api_key:
        msg = (
            "GEMINI_API_KEY environment variable not set. "
            "Set it with: export GEMINI_API_KEY='your-api-key'"
        )
        raise ValueError(msg)

    return api_key


def load_image_as_base64(image_path: Path) -> tuple[str, str]:
    """Load an image file and return base64 data and mime type.

    Args:
        image_path: Path to the image file.

    Returns:
        Tuple of (base64_encoded_data, mime_type).

    Raises:
        FileNotFoundError: If the image file doesn't exist.

    """
    if not image_path.exists():
        msg = f"Image file not found: {image_path}"
        raise FileNotFoundError(msg)

    suffix = image_path.suffix.lower()
    mime_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
    }

    mime_type = mime_types.get(suffix, "image/png")

    with open(image_path, "rb") as f:
        data = base64.standard_b64encode(f.read()).decode("utf-8")

    return data, mime_type


def decode_base64_image(base64_data: str) -> bytes:
    """Decode base64 image data to bytes.

    Args:
        base64_data: Base64-encoded image data.

    Returns:
        Raw image bytes.

    """
    return base64.standard_b64decode(base64_data)


def get_file_extension(mime_type: str) -> str:
    """Get file extension for a given MIME type.

    Args:
        mime_type: MIME type string (e.g., "image/png").

    Returns:
        File extension including the dot (e.g., ".png").

    """
    extensions = {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "image/webp": ".webp",
    }
    return extensions.get(mime_type, ".png")
