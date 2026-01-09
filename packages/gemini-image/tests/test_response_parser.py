"""Tests for response parser module."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from gemini_image.exceptions import GenerationError
from gemini_image.response_parser import (
    GenerationResponse,
    ThoughtImage,
    extract_safety_ratings,
    parse_response,
)


class TestThoughtImage:
    """Tests for ThoughtImage dataclass."""

    def test_format_detection(self, sample_image_bytes: bytes) -> None:
        """Test that format is detected from data."""
        thought = ThoughtImage(
            data=sample_image_bytes,
            mime_type="image/png",
            index=1,
        )
        assert thought.format == "png"

    def test_with_text(self) -> None:
        """Test thought image with reasoning text."""
        # Create minimal PNG data
        png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        thought = ThoughtImage(
            data=png_data,
            mime_type="image/png",
            index=1,
            text="Thinking about composition...",
        )
        assert thought.text == "Thinking about composition..."


class TestGenerationResponse:
    """Tests for GenerationResponse dataclass."""

    def test_has_image_true(self, sample_image_bytes: bytes) -> None:
        """Test has_image returns True when image data present."""
        response = GenerationResponse(
            image_data=sample_image_bytes,
            image_format="png",
        )
        assert response.has_image is True

    def test_has_image_false(self) -> None:
        """Test has_image returns False when no image data."""
        response = GenerationResponse()
        assert response.has_image is False

    def test_thought_count(self, sample_image_bytes: bytes) -> None:
        """Test thought_count returns correct number."""
        response = GenerationResponse(
            thought_images=[
                ThoughtImage(data=sample_image_bytes, mime_type="image/png", index=1),
                ThoughtImage(data=sample_image_bytes, mime_type="image/png", index=2),
            ]
        )
        assert response.thought_count == 2


class TestParseResponse:
    """Tests for parse_response function."""

    def test_parse_basic_response(
        self, mock_genai_response: MagicMock, sample_image_bytes: bytes
    ) -> None:
        """Test parsing a basic response with image."""
        result = parse_response(mock_genai_response)

        assert result.has_image
        assert result.image_data == sample_image_bytes
        assert result.image_format == "png"

    def test_parse_empty_response_raises(self) -> None:
        """Test that empty response raises GenerationError."""
        mock_response = MagicMock()
        mock_response.candidates = []

        with pytest.raises(GenerationError, match="No response candidates"):
            parse_response(mock_response)

    def test_parse_response_with_thoughts(
        self, sample_image_bytes: bytes
    ) -> None:
        """Test parsing response with thought images."""
        mock_response = MagicMock()

        # Create thought part
        thought_part = MagicMock()
        thought_part.thought = True
        thought_part.text = "Analyzing composition..."
        thought_part.inline_data = MagicMock()
        thought_part.inline_data.data = sample_image_bytes
        thought_part.inline_data.mime_type = "image/png"

        # Create final part
        final_part = MagicMock()
        final_part.thought = False
        final_part.text = None
        final_part.inline_data = MagicMock()
        final_part.inline_data.data = sample_image_bytes
        final_part.inline_data.mime_type = "image/png"
        final_part.thought_signature = None

        mock_candidate = MagicMock()
        mock_candidate.content.parts = [thought_part, final_part]
        mock_response.candidates = [mock_candidate]

        result = parse_response(mock_response)

        assert result.has_image
        assert result.thought_count == 1
        assert result.thought_images[0].text == "Analyzing composition..."

    def test_parse_response_with_text(self, sample_image_bytes: bytes) -> None:
        """Test parsing response with text response."""
        mock_response = MagicMock()

        # Create text part
        text_part = MagicMock()
        text_part.thought = False
        text_part.text = "Here is your image"
        text_part.inline_data = None

        # Create image part
        image_part = MagicMock()
        image_part.thought = False
        image_part.text = None
        image_part.inline_data = MagicMock()
        image_part.inline_data.data = sample_image_bytes
        image_part.inline_data.mime_type = "image/png"
        image_part.thought_signature = None

        mock_candidate = MagicMock()
        mock_candidate.content.parts = [text_part, image_part]
        mock_response.candidates = [mock_candidate]

        result = parse_response(mock_response)

        assert result.has_image
        assert result.text_response == "Here is your image"

    def test_parse_response_with_thought_signature(
        self, sample_image_bytes: bytes
    ) -> None:
        """Test parsing response with thought signature."""
        mock_response = MagicMock()

        mock_part = MagicMock()
        mock_part.thought = False
        mock_part.text = None
        mock_part.inline_data = MagicMock()
        mock_part.inline_data.data = sample_image_bytes
        mock_part.inline_data.mime_type = "image/png"
        mock_part.thought_signature = "signature_bytes_here"

        mock_candidate = MagicMock()
        mock_candidate.content.parts = [mock_part]
        mock_response.candidates = [mock_candidate]

        result = parse_response(mock_response)

        assert result.thought_signature == "signature_bytes_here"


class TestExtractSafetyRatings:
    """Tests for extract_safety_ratings function."""

    def test_extract_with_ratings(self) -> None:
        """Test extracting safety ratings from response."""
        mock_response = MagicMock()
        mock_rating = MagicMock()
        mock_rating.category = "HARM_CATEGORY_DANGEROUS"
        mock_rating.probability = "LOW"
        mock_rating.blocked = False

        mock_candidate = MagicMock()
        mock_candidate.safety_ratings = [mock_rating]
        mock_response.candidates = [mock_candidate]

        ratings = extract_safety_ratings(mock_response)

        assert len(ratings) == 1
        assert "category" in ratings[0]
        assert "probability" in ratings[0]

    def test_extract_empty_response(self) -> None:
        """Test extracting from response with no candidates."""
        mock_response = MagicMock()
        mock_response.candidates = []

        ratings = extract_safety_ratings(mock_response)
        assert ratings == []

    def test_extract_no_ratings(self) -> None:
        """Test extracting when no safety ratings present."""
        mock_response = MagicMock()
        mock_candidate = MagicMock()
        mock_candidate.safety_ratings = None
        mock_response.candidates = [mock_candidate]

        ratings = extract_safety_ratings(mock_response)
        assert ratings == []
