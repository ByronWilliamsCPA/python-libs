"""PROMPTS.md registry for documenting generated images.

This module manages a markdown file that documents all generated images,
their prompts, parameters, and metadata. This provides:
- Audit trail of generations
- Easy search and reference
- Reproducibility information
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from gemini_image.exceptions import FileOperationError

if TYPE_CHECKING:
    from gemini_image.models import AspectRatio, ImageSize, ModelKey

logger = structlog.get_logger(__name__)

# Default registry filename
DEFAULT_REGISTRY_NAME = "PROMPTS.md"

# Template for new registry file
REGISTRY_TEMPLATE = """# Image Generation Registry

This file documents all images generated using the Gemini Image library.

## Index

| Image | Model | Date | Type |
|-------|-------|------|------|

---

## Entries

"""

# Template for a single entry
ENTRY_TEMPLATE = """### {filename}

| Property | Value |
|----------|-------|
| **File** | `{filepath}` |
| **Model** | {model} |
| **Date** | {date} |
| **Type** | {image_type} |
| **Aspect Ratio** | {aspect_ratio} |
| **Size** | {image_size} |

**Prompt:**
```
{prompt}
```

{references_section}
---

"""


class PromptRegistry:
    """Manages a PROMPTS.md file for documenting image generations.

    The registry maintains a markdown file with:
    - An index table for quick reference
    - Detailed entries for each generation with full metadata
    - Idempotent updates (won't duplicate entries)

    Example:
        >>> registry = PromptRegistry(Path("output/PROMPTS.md"))
        >>> registry.add_entry(
        ...     image_path=Path("output/image.png"),
        ...     prompt="A beautiful sunset",
        ...     model="pro",
        ...     aspect_ratio="16:9",
        ...     image_size="2K",
        ... )

    """

    def __init__(self, registry_path: Path | None = None) -> None:
        """Initialize the registry.

        Args:
            registry_path: Path to the PROMPTS.md file. If not provided,
                uses PROMPTS.md in the current directory.

        """
        self.path = registry_path or Path(DEFAULT_REGISTRY_NAME)

    def _ensure_exists(self) -> None:
        """Ensure the registry file exists, creating it if needed."""
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with open(self.path, "w") as f:
                    f.write(REGISTRY_TEMPLATE)
                logger.info("registry_created", path=str(self.path))
            except OSError as e:
                raise FileOperationError(
                    f"Failed to create registry: {e}",
                    path=str(self.path),
                    operation="write",
                ) from e

    def _read_content(self) -> str:
        """Read the current registry content."""
        self._ensure_exists()
        try:
            with open(self.path) as f:
                return f.read()
        except OSError as e:
            raise FileOperationError(
                f"Failed to read registry: {e}",
                path=str(self.path),
                operation="read",
            ) from e

    def _write_content(self, content: str) -> None:
        """Write content to the registry."""
        try:
            with open(self.path, "w") as f:
                f.write(content)
        except OSError as e:
            raise FileOperationError(
                f"Failed to write registry: {e}",
                path=str(self.path),
                operation="write",
            ) from e

    def _entry_exists(self, content: str, filename: str) -> bool:
        """Check if an entry already exists for a filename."""
        # Look for the entry header
        pattern = rf"^### {re.escape(filename)}$"
        return bool(re.search(pattern, content, re.MULTILINE))

    def add_entry(
        self,
        image_path: Path,
        prompt: str,
        model: ModelKey,
        *,
        aspect_ratio: AspectRatio | None = None,
        image_size: ImageSize | None = None,
        reference_images: list[Path] | None = None,
        is_draft: bool = False,
    ) -> bool:
        """Add an entry to the registry.

        This method is idempotent - it won't add duplicate entries for
        the same filename.

        Args:
            image_path: Path to the generated image.
            prompt: The prompt used for generation.
            model: The model key used.
            aspect_ratio: The aspect ratio used (if any).
            image_size: The image size used (if any).
            reference_images: List of reference image paths used.
            is_draft: Whether this is a draft image.

        Returns:
            True if entry was added, False if it already existed.

        """
        content = self._read_content()
        filename = image_path.name

        # Check for existing entry
        if self._entry_exists(content, filename):
            logger.debug("registry_entry_exists", filename=filename)
            return False

        # Format the entry
        image_type = "Draft" if is_draft else "Final"
        date_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # Build references section
        references_section = ""
        if reference_images:
            ref_list = "\n".join(f"- `{p.name}`" for p in reference_images)
            references_section = f"**Reference Images:**\n{ref_list}\n\n"

        entry = ENTRY_TEMPLATE.format(
            filename=filename,
            filepath=str(image_path),
            model=model,
            date=date_str,
            image_type=image_type,
            aspect_ratio=aspect_ratio or "default",
            image_size=image_size or "default",
            prompt=prompt,
            references_section=references_section,
        )

        # Add to index table
        index_row = f"| {filename} | {model} | {date_str.split()[0]} | {image_type} |\n"

        # Find the index table and add row
        index_pattern = r"(\| Image \| Model \| Date \| Type \|\n\|[-|]+\|\n)"
        index_match = re.search(index_pattern, content)

        if index_match:
            # Insert row after table header
            insert_pos = index_match.end()
            content = content[:insert_pos] + index_row + content[insert_pos:]
        else:
            logger.warning("registry_index_not_found", path=str(self.path))

        # Add entry at the end (before final ---)
        if content.rstrip().endswith("---"):
            content = content.rstrip()[:-3] + entry
        else:
            content = content.rstrip() + "\n\n" + entry

        self._write_content(content)
        logger.info("registry_entry_added", filename=filename, model=model)
        return True

    def find_entry(self, filename: str) -> dict[str, str] | None:
        """Find an entry by filename.

        Args:
            filename: Name of the image file to find.

        Returns:
            Dictionary with entry metadata, or None if not found.

        """
        content = self._read_content()

        # Find the entry section
        pattern = rf"### {re.escape(filename)}\n(.*?)(?=\n### |\n---\n*$|\Z)"
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            return None

        entry_text = match.group(1)
        result: dict[str, str] = {"filename": filename}

        # Extract table values
        table_pattern = r"\| \*\*(\w+)\*\* \| (.+?) \|"
        for prop_match in re.finditer(table_pattern, entry_text):
            key = prop_match.group(1).lower()
            value = prop_match.group(2).strip().strip("`")
            result[key] = value

        # Extract prompt
        prompt_pattern = r"\*\*Prompt:\*\*\n```\n(.*?)\n```"
        prompt_match = re.search(prompt_pattern, entry_text, re.DOTALL)
        if prompt_match:
            result["prompt"] = prompt_match.group(1)

        return result

    def get_all_entries(self) -> list[dict[str, str]]:
        """Get all entries from the registry.

        Returns:
            List of dictionaries with entry metadata.

        """
        content = self._read_content()
        entries: list[dict[str, str]] = []

        # Find all entry headers
        pattern = r"### (.+?)\.(?:png|jpg|jpeg|gif|webp)\n"
        for match in re.finditer(pattern, content, re.IGNORECASE):
            filename = match.group(0).strip().lstrip("#").strip()
            entry = self.find_entry(filename)
            if entry:
                entries.append(entry)

        return entries
