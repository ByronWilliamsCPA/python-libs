"""Tests for PROMPTS.md registry module."""

from __future__ import annotations

from pathlib import Path

from gemini_image.registry import PromptRegistry


class TestPromptRegistry:
    """Tests for PromptRegistry class."""

    def test_create_registry(self, tmp_path: Path) -> None:
        """Test registry file is created when it doesn't exist."""
        registry_path = tmp_path / "PROMPTS.md"
        registry = PromptRegistry(registry_path)

        # Access should create the file
        registry._ensure_exists()

        assert registry_path.exists()
        content = registry_path.read_text()
        assert "Image Generation Registry" in content

    def test_add_entry(self, tmp_path: Path) -> None:
        """Test adding an entry to the registry."""
        registry_path = tmp_path / "PROMPTS.md"
        image_path = tmp_path / "test_image.png"
        image_path.touch()

        registry = PromptRegistry(registry_path)
        result = registry.add_entry(
            image_path=image_path,
            prompt="Test prompt for image generation",
            model="pro",
            aspect_ratio="16:9",
            image_size="2K",
        )

        assert result is True
        content = registry_path.read_text()
        assert "test_image.png" in content
        assert "Test prompt for image generation" in content
        assert "pro" in content
        assert "16:9" in content
        assert "2K" in content

    def test_add_entry_idempotent(self, tmp_path: Path) -> None:
        """Test that adding same entry twice is idempotent."""
        registry_path = tmp_path / "PROMPTS.md"
        image_path = tmp_path / "test_image.png"
        image_path.touch()

        registry = PromptRegistry(registry_path)

        # Add first time
        result1 = registry.add_entry(
            image_path=image_path,
            prompt="Test prompt",
            model="pro",
        )
        assert result1 is True

        # Add second time (same filename)
        result2 = registry.add_entry(
            image_path=image_path,
            prompt="Different prompt",
            model="flash",
        )
        assert result2 is False

        # Should only have one entry
        content = registry_path.read_text()
        assert content.count("### test_image.png") == 1

    def test_add_entry_with_references(self, tmp_path: Path) -> None:
        """Test adding entry with reference images."""
        registry_path = tmp_path / "PROMPTS.md"
        image_path = tmp_path / "output.png"
        ref1 = tmp_path / "ref1.png"
        ref2 = tmp_path / "ref2.png"
        image_path.touch()

        registry = PromptRegistry(registry_path)
        registry.add_entry(
            image_path=image_path,
            prompt="Test with refs",
            model="pro",
            reference_images=[ref1, ref2],
        )

        content = registry_path.read_text()
        assert "Reference Images" in content
        assert "ref1.png" in content
        assert "ref2.png" in content

    def test_add_draft_entry(self, tmp_path: Path) -> None:
        """Test adding a draft entry."""
        registry_path = tmp_path / "PROMPTS.md"
        image_path = tmp_path / "draft.png"
        image_path.touch()

        registry = PromptRegistry(registry_path)
        registry.add_entry(
            image_path=image_path,
            prompt="Draft prompt",
            model="pro",
            is_draft=True,
        )

        content = registry_path.read_text()
        assert "Draft" in content

    def test_find_entry(self, tmp_path: Path) -> None:
        """Test finding an entry by filename."""
        registry_path = tmp_path / "PROMPTS.md"
        image_path = tmp_path / "findme.png"
        image_path.touch()

        registry = PromptRegistry(registry_path)
        registry.add_entry(
            image_path=image_path,
            prompt="Find this prompt",
            model="flash",
        )

        result = registry.find_entry("findme.png")
        assert result is not None
        assert result["filename"] == "findme.png"
        assert result["prompt"] == "Find this prompt"

    def test_find_entry_not_found(self, tmp_path: Path) -> None:
        """Test finding non-existent entry returns None."""
        registry_path = tmp_path / "PROMPTS.md"
        registry = PromptRegistry(registry_path)
        registry._ensure_exists()

        result = registry.find_entry("nonexistent.png")
        assert result is None

    def test_index_table_updated(self, tmp_path: Path) -> None:
        """Test that the index table is updated when adding entries."""
        registry_path = tmp_path / "PROMPTS.md"
        image_path = tmp_path / "indexed.png"
        image_path.touch()

        registry = PromptRegistry(registry_path)
        registry.add_entry(
            image_path=image_path,
            prompt="Indexed entry",
            model="pro",
        )

        content = registry_path.read_text()
        # Check index table has the entry
        lines = content.split("\n")
        index_found = False
        for line in lines:
            if "| indexed.png |" in line:
                index_found = True
                assert "pro" in line
                break
        assert index_found, "Entry not found in index table"
