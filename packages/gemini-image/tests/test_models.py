"""Tests for model configurations."""

# Bandit B101 (assert_used) is expected in test files - pytest uses assert statements

from gemini_image.models import (
    ASPECT_RATIOS,
    DEFAULT_MODEL,
    IMAGE_SIZES,
    MAX_REFERENCE_IMAGES,
    MODELS,
)


class TestModelConfigurations:
    """Tests for model configuration constants."""

    def test_models_has_flash(self) -> None:
        """Test that flash model is defined."""
        assert "flash" in MODELS
        assert MODELS["flash"]["id"] == "gemini-2.5-flash-image"
        assert MODELS["flash"]["supports_image_config"] is False

    def test_models_has_pro(self) -> None:
        """Test that pro model is defined."""
        assert "pro" in MODELS
        assert MODELS["pro"]["id"] == "gemini-3-pro-image-preview"
        assert MODELS["pro"]["supports_image_config"] is True

    def test_default_model_is_pro(self) -> None:
        """Test that default model is pro."""
        assert DEFAULT_MODEL == "pro"

    def test_aspect_ratios(self) -> None:
        """Test that all expected aspect ratios are defined per API docs."""
        # Per API docs: 1:1, 2:3, 3:2, 3:4, 4:3, 4:5, 5:4, 9:16, 16:9, 21:9
        expected = [
            "1:1", "2:3", "3:2", "3:4", "4:3",
            "4:5", "5:4", "9:16", "16:9", "21:9",
        ]
        assert expected == ASPECT_RATIOS

    def test_image_sizes(self) -> None:
        """Test that all expected image sizes are defined."""
        expected = ["1K", "2K", "4K"]
        assert expected == IMAGE_SIZES

    def test_max_reference_images(self) -> None:
        """Test that reference image limits are defined correctly."""
        assert MAX_REFERENCE_IMAGES["flash"] == 3
        assert MAX_REFERENCE_IMAGES["pro"] == 14
