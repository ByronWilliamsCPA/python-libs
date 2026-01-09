"""Response parsing for Gemini API image generation.

This module handles parsing and processing of Gemini API responses,
extracting image data, thought images, signatures, and text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from gemini_image.exceptions import GenerationError
from gemini_image.io import detect_image_format, get_mime_type_for_format

logger = structlog.get_logger(__name__)


@dataclass
class ThoughtImage:
    """An intermediate thought image from the generation process.

    Attributes:
        data: Raw image bytes.
        mime_type: MIME type of the image.
        index: Index of this thought in the sequence.
        text: Optional reasoning text associated with this thought.

    """

    data: bytes
    mime_type: str
    index: int
    text: str | None = None

    @property
    def format(self) -> str:
        """Get the image format from the data."""
        return detect_image_format(self.data)


@dataclass
class GenerationResponse:
    """Parsed response from Gemini image generation API.

    This class provides a structured representation of the API response,
    separating the final image from intermediate thoughts.

    Attributes:
        image_data: Raw bytes of the final generated image.
        image_format: Detected format of the image ('png', 'jpeg', etc.).
        mime_type: MIME type of the image.
        thought_images: List of intermediate thought images (if thinking mode).
        thought_signature: Signature for thought continuity (if available).
        text_response: Any text in the response (model comments).

    """

    image_data: bytes | None = None
    image_format: str | None = None
    mime_type: str | None = None
    thought_images: list[ThoughtImage] = field(default_factory=list)
    thought_signature: str | bytes | None = None
    text_response: str | None = None

    @property
    def has_image(self) -> bool:
        """Check if the response contains a final image."""
        return self.image_data is not None

    @property
    def thought_count(self) -> int:
        """Get the number of thought images."""
        return len(self.thought_images)


def parse_response(response: Any, *, verbose: bool = False) -> GenerationResponse:
    """Parse a Gemini API response into a structured format.

    This function extracts all relevant data from the API response:
    - Final image data and format
    - Intermediate thought images (for thinking mode)
    - Thought signatures for continuity
    - Text responses and reasoning

    Args:
        response: Raw response from the Gemini API.
        verbose: If True, logs detailed parsing information.

    Returns:
        GenerationResponse with parsed data.

    Raises:
        GenerationError: If the response has no candidates or is blocked.

    """
    result = GenerationResponse()

    # Check for valid response
    if not response.candidates:
        _handle_empty_response(response)
        raise GenerationError(
            "No response candidates returned",
            details={"feedback": _get_feedback(response)},
        )

    # Process all parts in the response
    thought_index = 0

    for part in response.candidates[0].content.parts:
        is_thought = hasattr(part, "thought") and part.thought

        if is_thought:
            thought_index += 1
            _process_thought_part(part, thought_index, result, verbose=verbose)
        else:
            _process_final_part(part, result, verbose=verbose)

    # Detect format for final image
    if result.image_data:
        try:
            result.image_format = detect_image_format(result.image_data)
            result.mime_type = get_mime_type_for_format(result.image_format)
        except Exception as e:
            logger.warning("format_detection_failed", error=str(e))
            result.image_format = "png"
            result.mime_type = "image/png"

    if verbose and result.thought_count > 0:
        logger.info(
            "response_parsed",
            thought_count=result.thought_count,
            has_image=result.has_image,
            has_signature=result.thought_signature is not None,
        )

    return result


def _handle_empty_response(response: Any) -> None:
    """Log details about an empty response."""
    feedback = _get_feedback(response)
    if feedback:
        logger.error("generation_blocked", feedback=feedback)
    else:
        logger.error("generation_failed_no_candidates")


def _get_feedback(response: Any) -> dict[str, Any] | None:
    """Extract feedback from response if available."""
    if hasattr(response, "prompt_feedback"):
        feedback = response.prompt_feedback
        if hasattr(feedback, "__dict__"):
            return dict(feedback.__dict__)
        return {"raw": str(feedback)}
    return None


def _process_thought_part(
    part: Any,
    index: int,
    result: GenerationResponse,
    *,
    verbose: bool = False,
) -> None:
    """Process a thought (intermediate reasoning) part."""
    if verbose:
        logger.debug("processing_thought", index=index)

    # Extract thought text
    thought_text = None
    if part.text is not None:
        thought_text = part.text
        if verbose:
            logger.debug("thought_reasoning", index=index, text=thought_text[:100])

    # Extract thought image
    if part.inline_data is not None:
        thought_image = ThoughtImage(
            data=part.inline_data.data,
            mime_type=part.inline_data.mime_type,
            index=index,
            text=thought_text,
        )
        result.thought_images.append(thought_image)

        if verbose:
            logger.debug(
                "thought_image_extracted",
                index=index,
                size=len(thought_image.data),
            )


def _process_final_part(
    part: Any,
    result: GenerationResponse,
    *,
    verbose: bool = False,
) -> None:
    """Process a final (non-thought) part."""
    # Handle image data
    if part.inline_data is not None:
        result.image_data = part.inline_data.data
        result.mime_type = part.inline_data.mime_type

        if verbose:
            logger.debug(
                "final_image_extracted",
                size=len(result.image_data),
                mime_type=result.mime_type,
            )

        # Extract thought signature if available
        if hasattr(part, "thought_signature") and part.thought_signature:
            result.thought_signature = part.thought_signature
            if verbose:
                sig_preview = str(result.thought_signature)[:50]
                logger.debug("thought_signature_extracted", preview=sig_preview)

    # Handle text response
    elif part.text is not None:
        result.text_response = part.text

        if verbose:
            logger.debug("text_response", text=part.text[:100])

        # Check for thought signature in text part
        if hasattr(part, "thought_signature") and part.thought_signature:
            result.thought_signature = part.thought_signature


def extract_safety_ratings(response: Any) -> list[dict[str, Any]]:
    """Extract safety ratings from a response.

    Args:
        response: Raw response from the Gemini API.

    Returns:
        List of safety rating dictionaries.

    """
    ratings: list[dict[str, Any]] = []

    if not response.candidates:
        return ratings

    candidate = response.candidates[0]
    if hasattr(candidate, "safety_ratings") and candidate.safety_ratings:
        for rating in candidate.safety_ratings:
            rating_dict: dict[str, Any] = {}
            if hasattr(rating, "category"):
                rating_dict["category"] = str(rating.category)
            if hasattr(rating, "probability"):
                rating_dict["probability"] = str(rating.probability)
            if hasattr(rating, "blocked"):
                rating_dict["blocked"] = rating.blocked
            ratings.append(rating_dict)

    return ratings
