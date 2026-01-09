"""Core image generation functions using Google Gemini.

This module provides the main entry points for image generation:
- generate_image(): Single image generation
- generate_batch(): Batch processing multiple prompts
- generate_story_sequence(): Multi-part story generation
- finalize_draft(): Draft-to-final upscaling
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from gemini_image.client import GeminiClient, _get_genai
from gemini_image.exceptions import ValidationError
from gemini_image.io import (
    get_extension_for_format,
    load_metadata,
    save_image,
    save_metadata,
)
from gemini_image.models import (
    ASPECT_RATIOS,
    DEFAULT_MODEL,
    IMAGE_SIZES,
    MODELS,
)
from gemini_image.registry import PromptRegistry
from gemini_image.response_parser import GenerationResponse, parse_response

if TYPE_CHECKING:
    from gemini_image.models import AspectRatio, ImageSize, ModelKey

logger = structlog.get_logger(__name__)


def generate_image(
    prompt: str,
    model_key: ModelKey = DEFAULT_MODEL,
    reference_images: list[Path] | None = None,
    output_path: Path | None = None,
    output_dir: Path | None = None,
    aspect_ratio: AspectRatio | None = None,
    image_size: ImageSize | None = None,
    use_search: bool = False,
    save_thoughts: bool = False,
    verbose: bool = False,
    is_draft: bool = False,
    *,
    document: bool = True,
    registry_path: Path | None = None,
    save_metadata_file: bool = True,
) -> Path | None:
    """Generate an image using Gemini.

    Args:
        prompt: Text description of the image to generate.
        model_key: Model to use ('flash' or 'pro').
        reference_images: Optional list of reference images for editing/style.
        output_path: Optional output file path. If not provided, generates
            a timestamped filename.
        output_dir: Optional output directory. Defaults to current directory.
        aspect_ratio: Aspect ratio for pro model (e.g., "16:9", "1:1").
        image_size: Image size for pro model ("1K", "2K", "4K").
        use_search: Enable Google Search grounding (pro model only).
        save_thoughts: Save intermediate thought images (pro model only).
        verbose: Show detailed thinking process and thought signatures.
        is_draft: Generate at 1K resolution for fast iteration.
        document: If True, adds entry to PROMPTS.md registry.
        registry_path: Path to PROMPTS.md file (default: output_dir/PROMPTS.md).
        save_metadata_file: If True, saves JSON metadata sidecar file.

    Returns:
        Path to the generated image, or None on failure.

    Raises:
        ValidationError: If model_key, aspect_ratio, or image_size is invalid.
        ConfigurationError: If API key is missing.
        GenerationError: If image generation fails.

    """
    # Validate inputs
    _validate_model_key(model_key)
    _validate_aspect_ratio(aspect_ratio)
    _validate_image_size(image_size)

    model_config = MODELS[model_key]

    logger.info(
        "generating_image",
        model=model_config["name"],
        prompt_preview=prompt[:50] + "..." if len(prompt) > 50 else prompt,
        is_draft=is_draft,
    )

    # Initialize client and types
    client = GeminiClient()
    _, types = _get_genai()

    # Build content parts
    contents = _build_contents(reference_images, prompt, types, verbose=verbose)

    # Build generation config
    effective_size = "1K" if is_draft else image_size
    config = _build_generation_config(
        model_config=model_config,
        aspect_ratio=aspect_ratio,
        image_size=effective_size,
        use_search=use_search,
        types=types,
        verbose=verbose,
    )

    # Generate image
    response = client.generate_content(
        model=model_config["id"],
        contents=contents,
        config=config,
    )

    # Parse response
    parsed = parse_response(response, verbose=verbose)

    if not parsed.has_image:
        logger.error("generation_failed_no_image")
        return None

    # Determine output path
    if output_dir is None:
        output_dir = Path.cwd()

    final_path = _determine_output_path(
        output_path=output_path,
        output_dir=output_dir,
        image_format=parsed.image_format or "png",
        is_draft=is_draft,
    )

    # Save the image (with format correction)
    assert parsed.image_data is not None  # We checked has_image above
    saved_path = save_image(parsed.image_data, final_path, correct_extension=True)

    # Save thought images if requested
    if save_thoughts and parsed.thought_images:
        _save_thought_images(parsed, saved_path, output_dir, verbose=verbose)

    # Save metadata sidecar
    if save_metadata_file:
        save_metadata(
            saved_path,
            prompt=prompt,
            model=model_key,
            aspect_ratio=aspect_ratio,
            image_size=effective_size,
            reference_images=reference_images,
            thought_signature=(
                str(parsed.thought_signature) if parsed.thought_signature else None
            ),
            is_draft=is_draft,
        )

    # Add to registry
    if document:
        reg_path = registry_path or (output_dir / "PROMPTS.md")
        registry = PromptRegistry(reg_path)
        registry.add_entry(
            image_path=saved_path,
            prompt=prompt,
            model=model_key,
            aspect_ratio=aspect_ratio,
            image_size=effective_size,
            reference_images=reference_images,
            is_draft=is_draft,
        )

    logger.info("image_generated", path=str(saved_path))
    return saved_path


def generate_batch(
    prompts: list[dict[str, object]],
    output_dir: Path | None = None,
    *,
    parallel: int = 1,
    resume: bool = True,
    document: bool = True,
    show_progress: bool = True,
) -> list[Path | None]:
    """Generate multiple images from a list of prompts.

    Each item in the prompts list should be a dictionary with at least a
    'prompt' key. Other supported keys match generate_image() parameters:
    - prompt (required): Text description
    - output_path: Specific output path
    - model_key: Model to use (default: flash)
    - aspect_ratio: Aspect ratio for pro model
    - image_size: Image size
    - reference_images: List of reference image paths

    Args:
        prompts: List of prompt dictionaries.
        output_dir: Output directory for generated images.
        parallel: Number of concurrent generations (currently only 1 supported).
        resume: If True, skip prompts that already have output files.
        document: If True, adds entries to PROMPTS.md registry.
        show_progress: If True, displays a progress bar.

    Returns:
        List of paths to generated images (None for failed generations).

    Raises:
        ValidationError: If prompts list is empty or a prompt is invalid.

    Example:
        >>> prompts = [
        ...     {"prompt": "A sunset over mountains", "aspect_ratio": "16:9"},
        ...     {"prompt": "A forest in autumn", "model_key": "pro"},
        ... ]
        >>> results = generate_batch(prompts, output_dir=Path("./images"))

    """
    if not prompts:
        raise ValidationError(
            "Prompts list cannot be empty",
            field="prompts",
            value=[],
        )

    if parallel > 1:
        logger.warning(
            "parallel_not_implemented",
            requested=parallel,
            using=1,
            message="Parallel batch processing not yet implemented",
        )
        parallel = 1

    if output_dir is None:
        output_dir = Path.cwd()
    output_dir.mkdir(parents=True, exist_ok=True)

    results: list[Path | None] = []

    logger.info(
        "batch_generation_started",
        total_prompts=len(prompts),
        output_dir=str(output_dir),
    )

    # Import progress bar conditionally
    progress_context: object
    if show_progress:
        try:
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

            progress_context = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            )
        except ImportError:
            logger.debug("rich_not_available_using_simple_progress")
            progress_context = None
    else:
        progress_context = None

    def process_prompts(progress: object | None) -> list[Path | None]:
        """Process prompts with optional progress tracking."""
        batch_results: list[Path | None] = []

        task_id = None
        if progress is not None:
            task_id = progress.add_task(  # type: ignore[union-attr]
                f"Generating {len(prompts)} images...",
                total=len(prompts),
            )

        for idx, prompt_config in enumerate(prompts, 1):
            # Validate prompt config
            if not isinstance(prompt_config, dict):
                logger.error(
                    "invalid_prompt_config",
                    index=idx,
                    type=type(prompt_config).__name__,
                )
                batch_results.append(None)
                if progress is not None and task_id is not None:
                    progress.advance(task_id)  # type: ignore[union-attr]
                continue

            prompt_text = prompt_config.get("prompt")
            if not prompt_text or not isinstance(prompt_text, str):
                logger.error("missing_prompt_text", index=idx)
                batch_results.append(None)
                if progress is not None and task_id is not None:
                    progress.advance(task_id)  # type: ignore[union-attr]
                continue

            # Check if output already exists (resume support)
            output_path = prompt_config.get("output_path")
            if output_path is not None:
                output_path = Path(output_path)  # type: ignore[arg-type]
            if resume and output_path is not None and output_path.exists():
                logger.info("skipping_existing", index=idx, path=str(output_path))
                batch_results.append(output_path)
                if progress is not None and task_id is not None:
                    progress.advance(task_id)  # type: ignore[union-attr]
                continue

            # Extract other parameters
            model_key = prompt_config.get("model_key", DEFAULT_MODEL)
            aspect_ratio = prompt_config.get("aspect_ratio")
            image_size = prompt_config.get("image_size")
            reference_images = prompt_config.get("reference_images")

            if reference_images:
                reference_images = [Path(p) for p in reference_images]  # type: ignore[union-attr]

            logger.info(
                "batch_generating",
                index=idx,
                total=len(prompts),
                prompt_preview=prompt_text[:30] + "..." if len(prompt_text) > 30 else prompt_text,
            )

            try:
                result = generate_image(
                    prompt=prompt_text,
                    model_key=model_key,  # type: ignore[arg-type]
                    reference_images=reference_images,  # type: ignore[arg-type]
                    output_path=output_path,
                    output_dir=output_dir,
                    aspect_ratio=aspect_ratio,  # type: ignore[arg-type]
                    image_size=image_size,  # type: ignore[arg-type]
                    document=document,
                )
                batch_results.append(result)
            except Exception as e:
                logger.error(
                    "batch_item_failed",
                    index=idx,
                    error=str(e),
                )
                batch_results.append(None)

            if progress is not None and task_id is not None:
                progress.advance(task_id)  # type: ignore[union-attr]

        return batch_results

    # Run with or without progress bar
    if progress_context is not None:
        with progress_context:  # type: ignore[union-attr]
            results = process_prompts(progress_context)
    else:
        results = process_prompts(None)

    # Summary
    successful = sum(1 for r in results if r is not None)
    logger.info(
        "batch_generation_complete",
        successful=successful,
        failed=len(prompts) - successful,
        total=len(prompts),
    )

    return results


def generate_story_sequence(
    base_prompt: str,
    num_parts: int,
    model_key: ModelKey = DEFAULT_MODEL,
    output_prefix: Path | None = None,
    output_dir: Path | None = None,
    aspect_ratio: AspectRatio | None = None,
    image_size: ImageSize | None = None,
    verbose: bool = False,
    *,
    resume: bool = True,
    document: bool = True,
) -> list[Path]:
    """Generate a multi-part story sequence with visual continuity.

    Each subsequent image uses the previous image as a reference for
    visual continuity.

    Args:
        base_prompt: Base story description.
        num_parts: Number of story parts to generate.
        model_key: Model to use.
        output_prefix: Prefix for output files (e.g., "story" ->
            story_part1.png, story_part2.png).
        output_dir: Output directory for generated images.
        aspect_ratio: Aspect ratio for all images.
        image_size: Image size for all images.
        verbose: Show detailed process.
        resume: If True, skips parts that already exist.
        document: If True, adds entries to PROMPTS.md registry.

    Returns:
        List of paths to generated images.

    Raises:
        ValidationError: If num_parts < 1.

    """
    if num_parts < 1:
        raise ValidationError(
            "Number of story parts must be at least 1",
            field="num_parts",
            value=num_parts,
        )

    if output_dir is None:
        output_dir = Path.cwd()

    if output_prefix is None:
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_prefix = Path(f"story_{timestamp}")

    generated_images: list[Path] = []
    previous_image_path: Path | None = None

    logger.info(
        "generating_story_sequence",
        num_parts=num_parts,
        base_prompt=base_prompt[:50] + "..." if len(base_prompt) > 50 else base_prompt,
    )

    for part_num in range(1, num_parts + 1):
        # Build output path for this part
        output_path = output_dir / f"{output_prefix.stem}_part{part_num}.png"

        # Check if we should resume from existing
        if resume and output_path.exists():
            logger.info("skipping_existing_part", part=part_num, path=str(output_path))
            generated_images.append(output_path)
            previous_image_path = output_path
            continue

        # Build prompt for this part
        part_prompt = _build_story_prompt(base_prompt, part_num, num_parts)

        logger.info("generating_story_part", part=part_num, total=num_parts)

        # Build reference images list
        reference_images = [previous_image_path] if previous_image_path else None

        # Generate this part
        result = generate_image(
            prompt=part_prompt,
            model_key=model_key,
            reference_images=reference_images,
            output_path=output_path,
            output_dir=output_dir,
            aspect_ratio=aspect_ratio,
            image_size=image_size,
            use_search=False,
            save_thoughts=False,
            verbose=verbose,
            document=document,
        )

        if result:
            generated_images.append(result)
            previous_image_path = result
            logger.info("story_part_complete", part=part_num, path=str(result))
        else:
            logger.error("story_part_failed", part=part_num)
            break

    logger.info(
        "story_sequence_complete",
        generated=len(generated_images),
        total=num_parts,
    )

    return generated_images


def finalize_draft(
    draft_path: Path,
    prompt: str | None = None,
    model_key: ModelKey = DEFAULT_MODEL,
    output_path: Path | None = None,
    output_dir: Path | None = None,
    aspect_ratio: AspectRatio | None = None,
    image_size: ImageSize | None = None,
    verbose: bool = False,
    *,
    document: bool = True,
) -> Path | None:
    """Finalize a draft image by regenerating at higher resolution.

    This function attempts to read the original prompt from the draft's
    metadata sidecar file. If available, it uses that prompt for better
    reproduction fidelity.

    Args:
        draft_path: Path to the draft image.
        prompt: Optional refinement prompt. If not provided, uses the
            original prompt from metadata or a default upscaling prompt.
        model_key: Model to use.
        output_path: Output path for the final image.
        output_dir: Output directory.
        aspect_ratio: Aspect ratio (default: "16:9").
        image_size: Target resolution (default: "2K").
        verbose: Show detailed process.
        document: If True, adds entry to PROMPTS.md registry.

    Returns:
        Path to the finalized image, or None on failure.

    Raises:
        FileOperationError: If the draft image doesn't exist.

    """
    from gemini_image.exceptions import FileOperationError

    if not draft_path.exists():
        raise FileOperationError(
            f"Draft image not found: {draft_path}",
            path=str(draft_path),
            operation="read",
        )

    # Try to load original metadata
    metadata = load_metadata(draft_path)
    original_prompt = None

    if metadata:
        original_prompt = metadata.get("prompt")
        if verbose and original_prompt:
            logger.info("using_original_prompt", preview=original_prompt[:50])

    # Determine final resolution
    final_size = image_size or "2K"
    final_aspect = aspect_ratio or "16:9"

    logger.info(
        "finalizing_draft",
        draft=str(draft_path),
        target_size=final_size,
        target_aspect=final_aspect,
    )

    # Use provided prompt, original prompt, or default
    final_prompt = prompt or original_prompt or (
        "Recreate this image at higher resolution with the same "
        "composition, style, and details"
    )

    # Determine output path
    if output_path is None:
        output_path = Path(f"{draft_path.stem}_final.png")

    result = generate_image(
        prompt=final_prompt,
        model_key=model_key,
        reference_images=[draft_path],
        output_path=output_path,
        output_dir=output_dir,
        aspect_ratio=final_aspect,
        image_size=final_size,
        verbose=verbose,
        is_draft=False,
        document=document,
    )

    if result:
        logger.info(
            "finalization_complete",
            draft=str(draft_path),
            final=str(result),
            size=final_size,
        )

    return result


# --- Helper Functions ---


def _validate_model_key(model_key: str) -> None:
    """Validate that the model key is valid."""
    if model_key not in MODELS:
        raise ValidationError(
            f"Unknown model '{model_key}'",
            field="model_key",
            value=model_key,
            valid_options=list(MODELS.keys()),
        )


def _validate_aspect_ratio(aspect_ratio: str | None) -> None:
    """Validate that the aspect ratio is valid."""
    if aspect_ratio is not None and aspect_ratio not in ASPECT_RATIOS:
        raise ValidationError(
            f"Invalid aspect ratio '{aspect_ratio}'",
            field="aspect_ratio",
            value=aspect_ratio,
            valid_options=ASPECT_RATIOS,
        )


def _validate_image_size(image_size: str | None) -> None:
    """Validate that the image size is valid."""
    if image_size is not None and image_size not in IMAGE_SIZES:
        raise ValidationError(
            f"Invalid image size '{image_size}'",
            field="image_size",
            value=image_size,
            valid_options=IMAGE_SIZES,
        )


def _build_contents(
    reference_images: list[Path] | None,
    prompt: str,
    types: object,
    *,
    verbose: bool = False,
) -> list[object]:
    """Build the contents list for the API request."""
    contents: list[object] = []

    if reference_images:
        for img_path in reference_images:
            if not img_path.exists():
                logger.warning("reference_image_not_found", path=str(img_path))
                continue

            logger.debug("including_reference_image", path=str(img_path))

            # Load image data
            with open(img_path, "rb") as f:
                data = f.read()

            # Detect MIME type from extension (will be validated by API)
            suffix = img_path.suffix.lower()
            mime_types = {
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".gif": "image/gif",
                ".webp": "image/webp",
            }
            mime_type = mime_types.get(suffix, "image/png")

            # Add as Part
            contents.append(
                types.Part.from_bytes(  # type: ignore[union-attr]
                    data=data,
                    mime_type=mime_type,
                )
            )

    # Add the text prompt
    contents.append(prompt)
    return contents


def _build_generation_config(
    model_config: dict[str, object],
    aspect_ratio: str | None,
    image_size: str | None,
    use_search: bool,
    types: object,
    *,
    verbose: bool = False,
) -> object:
    """Build the generation config for the API request."""
    config_kwargs: dict[str, object] = {
        "response_modalities": ["IMAGE", "TEXT"],
    }

    # Add image config for pro model
    if model_config.get("supports_image_config"):
        image_config_kwargs: dict[str, str] = {}

        if aspect_ratio:
            image_config_kwargs["aspect_ratio"] = aspect_ratio
            logger.debug("config_aspect_ratio", value=aspect_ratio)

        if image_size:
            image_config_kwargs["image_size"] = image_size
            logger.debug("config_image_size", value=image_size)

        if image_config_kwargs:
            config_kwargs["image_config"] = types.ImageConfig(**image_config_kwargs)  # type: ignore[union-attr]

        # Add Google Search grounding if requested
        if use_search:
            config_kwargs["tools"] = [{"google_search": {}}]  # type: ignore[typeddict-item]
            logger.debug("config_search_enabled")

    return types.GenerateContentConfig(**config_kwargs)  # type: ignore[union-attr]


def _determine_output_path(
    output_path: Path | None,
    output_dir: Path,
    image_format: str,
    is_draft: bool,
) -> Path:
    """Determine the final output path."""
    if output_path is not None:
        # Honor absolute paths as-is
        if output_path.is_absolute():
            return output_path
        return output_dir / output_path

    # Generate timestamped filename
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    ext = get_extension_for_format(image_format)
    prefix = "draft_" if is_draft else "generated_"
    return output_dir / f"{prefix}{timestamp}{ext}"


def _save_thought_images(
    parsed: GenerationResponse,
    main_image_path: Path,
    output_dir: Path,
    *,
    verbose: bool = False,
) -> list[Path]:
    """Save thought images alongside the main image."""
    saved_paths: list[Path] = []

    for thought in parsed.thought_images:
        ext = get_extension_for_format(thought.format)
        thought_path = output_dir / f"{main_image_path.stem}_thought{thought.index}{ext}"

        save_image(thought.data, thought_path, correct_extension=True)
        saved_paths.append(thought_path)

        if verbose:
            logger.info(
                "thought_image_saved",
                index=thought.index,
                path=str(thought_path),
            )

    return saved_paths


def _build_story_prompt(base_prompt: str, part_num: int, total_parts: int) -> str:
    """Build the prompt for a specific story part."""
    if part_num == 1:
        return (
            f"{base_prompt}\n\n"
            f"This is part 1 of {total_parts}. Create the opening scene that "
            "establishes the context and visual style for the entire sequence."
        )
    if part_num == total_parts:
        return (
            f"This is part {part_num} of {total_parts}, the final scene. "
            "Building on the previous image, create a concluding scene that "
            "resolves the narrative. Maintain visual consistency with the "
            "established style."
        )
    return (
        f"This is part {part_num} of {total_parts}. Building on the previous "
        "image, advance the narrative while maintaining visual consistency "
        "with the established style."
    )
