"""Model configurations and type definitions for Gemini image generation."""

from __future__ import annotations

from typing import Literal, TypedDict

# Type aliases for model configuration
ModelKey = Literal["flash", "pro"]
AspectRatio = Literal["1:1", "2:3", "3:2", "3:4", "4:3", "4:5", "5:4", "9:16", "16:9", "21:9"]
ImageSize = Literal["1K", "2K", "4K"]

# Reference image limits per model
MAX_REFERENCE_IMAGES: dict[ModelKey, int] = {
    "flash": 3,
    "pro": 14,
}


class ModelConfig(TypedDict):
    """Configuration for a Gemini image generation model."""

    id: str
    name: str
    description: str
    supports_image_config: bool


# Model configurations
# Note: Actual API model IDs are gemini-2.5-flash-image and gemini-3-pro-image-preview
MODELS: dict[ModelKey, ModelConfig] = {
    "flash": {
        "id": "gemini-2.5-flash-image",
        "name": "Nano Banana (Gemini 2.5 Flash)",
        "description": "Fast image generation model",
        "supports_image_config": False,
    },
    "pro": {
        "id": "gemini-3-pro-image-preview",
        "name": "Nano Banana Pro (Gemini 3 Pro)",
        "description": "4K resolution, better text rendering, Google Search grounding, thinking mode",
        "supports_image_config": True,
    },
}

DEFAULT_MODEL: ModelKey = "pro"

# Valid aspect ratios (all models)
# Per API docs: 1:1, 2:3, 3:2, 3:4, 4:3, 4:5, 5:4, 9:16, 16:9, 21:9
ASPECT_RATIOS: list[AspectRatio] = [
    "1:1",   # Square
    "2:3",   # Portrait (2x3)
    "3:2",   # Landscape (3x2)
    "3:4",   # Portrait (3x4)
    "4:3",   # Standard landscape
    "4:5",   # Portrait (Instagram)
    "5:4",   # Landscape (5x4)
    "9:16",  # Vertical/mobile
    "16:9",  # Widescreen
    "21:9",  # Ultra-wide/cinematic
]

# Valid image sizes for pro model
IMAGE_SIZES: list[ImageSize] = ["1K", "2K", "4K"]
