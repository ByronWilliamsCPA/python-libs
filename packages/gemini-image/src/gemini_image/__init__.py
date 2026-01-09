"""Gemini Image Generation Library.

A comprehensive image generation system built on Google's Gemini models.

Features:
    - Text-to-image generation with configurable resolution and aspect ratio
    - Reference-based image editing and refinement
    - Multi-part story sequence generation with visual continuity
    - Draft-then-finalize workflow for cost optimization
    - Thinking mode with intermediate image visualization
    - Automatic PROMPTS.md registry for tracking generations
    - Magic byte format detection for API mismatch correction
    - Retry logic with exponential backoff for resilience

Models:
    - flash: Gemini 2.5 Flash (fast generation)
    - pro: Gemini 3 Pro (4K, better text rendering, thinking mode)

Example:
    >>> from gemini_image import generate_image, MODELS
    >>> result = generate_image("A futuristic city at sunset")
    >>> print(f"Image saved to: {result}")

"""

from gemini_image.client import GeminiClient, get_api_key
from gemini_image.exceptions import (
    APIError,
    ConfigurationError,
    ContentBlockedError,
    FileOperationError,
    FormatDetectionError,
    GeminiImageError,
    GenerationError,
    RateLimitError,
    ServerError,
    ValidationError,
)
from gemini_image.generator import (
    finalize_draft,
    generate_batch,
    generate_image,
    generate_story_sequence,
)
from gemini_image.io import (
    detect_image_format,
    load_metadata,
    save_image,
    save_metadata,
)
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
from gemini_image.registry import PromptRegistry
from gemini_image.response_parser import (
    GenerationResponse,
    ThoughtImage,
    parse_response,
)

__all__ = [
    "APIError",
    "ASPECT_RATIOS",
    "AspectRatio",
    "ConfigurationError",
    "ContentBlockedError",
    "DEFAULT_MODEL",
    "FileOperationError",
    "FormatDetectionError",
    "GeminiClient",
    "GeminiImageError",
    "GenerationError",
    "GenerationResponse",
    "IMAGE_SIZES",
    "ImageSize",
    "MODELS",
    "ModelConfig",
    "ModelKey",
    "PromptRegistry",
    "RateLimitError",
    "ServerError",
    "ThoughtImage",
    "ValidationError",
    "detect_image_format",
    "finalize_draft",
    "generate_batch",
    "generate_image",
    "generate_story_sequence",
    "get_api_key",
    "load_metadata",
    "parse_response",
    "save_image",
    "save_metadata",
]

__version__ = "0.2.0"
