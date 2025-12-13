"""Gemini Image Generation Library.

A comprehensive image generation system built on Google's Gemini models.

Features:
    - Text-to-image generation with configurable resolution and aspect ratio
    - Reference-based image editing and refinement
    - Multi-part story sequence generation with visual continuity
    - Draft-then-finalize workflow for cost optimization
    - Thinking mode with intermediate image visualization

Models:
    - flash: Gemini 2.5 Flash (fast generation)
    - pro: Gemini 3 Pro (4K, better text rendering, thinking mode)

Example:
    >>> from gemini_image import generate_image, MODELS
    >>> result = generate_image("A futuristic city at sunset")
    >>> print(f"Image saved to: {result}")

"""

from gemini_image.generator import generate_image, generate_story_sequence
from gemini_image.models import (
    ASPECT_RATIOS,
    DEFAULT_MODEL,
    IMAGE_SIZES,
    MODELS,
    AspectRatio,
    ImageSize,
    ModelConfig,
    ModelKey,
)

__all__ = [
    "ASPECT_RATIOS",
    "DEFAULT_MODEL",
    "IMAGE_SIZES",
    "MODELS",
    "AspectRatio",
    "ImageSize",
    "ModelConfig",
    "ModelKey",
    "generate_image",
    "generate_story_sequence",
]

__version__ = "0.1.0"
