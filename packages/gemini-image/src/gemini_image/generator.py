"""Core image generation functions using Google Gemini.

Note: This module has complexity warnings (C901, PLR0912, PLR0915) due to the
comprehensive response handling logic inherited from the source script.
The google-genai types are dynamically loaded, causing reportUnknown* warnings.
"""
# ruff: noqa: C901, PLR0912, PLR0915, PLC0415

from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gemini_image.models import (
    ASPECT_RATIOS,
    DEFAULT_MODEL,
    IMAGE_SIZES,
    MODELS,
    AspectRatio,
    ImageSize,
    ModelKey,
)
from gemini_image.utils import (
    get_api_key,
    get_file_extension,
    load_image_as_base64,
)

# Lazy import for google.genai
_genai = None
_types = None


def _get_genai() -> tuple[Any, Any]:
    """Lazy import google.genai to avoid import errors when not installed."""
    global _genai, _types  # noqa: PLW0603
    if _genai is None:
        try:
            from google import genai
            from google.genai import types

            _genai = genai
            _types = types
        except ImportError as e:
            msg = (
                "google-genai package not installed. "
                "Install with: pip install google-genai"
            )
            raise ImportError(msg) from e
    return _genai, _types


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

    Returns:
        Path to the generated image, or None on failure.

    Raises:
        ValueError: If model_key is invalid or API key is missing.
        ImportError: If google-genai is not installed.

    """
    genai, types = _get_genai()
    api_key = get_api_key()

    if model_key not in MODELS:
        msg = f"Unknown model '{model_key}'. Valid options: {list(MODELS.keys())}"
        raise ValueError(msg)

    model_config = MODELS[model_key]
    model_id = model_config["id"]

    if verbose:
        print(f"Using model: {model_config['name']}")  # noqa: T201
        print(f"Prompt: {prompt[:100]}{'...' if len(prompt) > 100 else ''}")  # noqa: T201

    # Initialize client
    client = genai.Client(api_key=api_key)

    # Build the content parts
    contents: list = []

    # Add reference images if provided
    if reference_images:
        for img_path in reference_images:
            if not img_path.exists():
                if verbose:
                    print(f"Warning: Reference image not found: {img_path}")  # noqa: T201
                continue

            if verbose:
                print(f"Including reference image: {img_path}")  # noqa: T201
            img_data, mime_type = load_image_as_base64(img_path)
            contents.append(
                types.Part.from_bytes(
                    data=base64.standard_b64decode(img_data),
                    mime_type=mime_type,
                )
            )

    # Add the text prompt
    contents.append(prompt)

    # Build config kwargs
    config_kwargs = {
        "response_modalities": ["IMAGE", "TEXT"],
    }

    # Override size to 1K if draft mode
    effective_size = "1K" if is_draft else image_size

    # Add image config for pro model
    if model_config.get("supports_image_config"):
        image_config_kwargs = {}
        if aspect_ratio:
            if aspect_ratio not in ASPECT_RATIOS:
                if verbose:
                    print(  # noqa: T201
                        f"Warning: Invalid aspect ratio '{aspect_ratio}'. "
                        f"Valid: {ASPECT_RATIOS}"
                    )
            else:
                image_config_kwargs["aspect_ratio"] = aspect_ratio
                if verbose:
                    print(f"Aspect ratio: {aspect_ratio}")  # noqa: T201
        if effective_size:
            if effective_size not in IMAGE_SIZES:
                if verbose:
                    print(  # noqa: T201
                        f"Warning: Invalid image size '{effective_size}'. "
                        f"Valid: {IMAGE_SIZES}"
                    )
            else:
                image_config_kwargs["image_size"] = effective_size
                if verbose:
                    print(f"Image size: {effective_size}")  # noqa: T201

        if image_config_kwargs:
            config_kwargs["image_config"] = types.ImageConfig(**image_config_kwargs)

        # Add Google Search grounding if requested
        if use_search:
            config_kwargs["tools"] = [{"google_search": {}}]
            if verbose:
                print("Google Search grounding: enabled")  # noqa: T201

    # Configure generation
    generate_config = types.GenerateContentConfig(**config_kwargs)

    if verbose:
        print("Generating image...")  # noqa: T201

    response = client.models.generate_content(
        model=model_id,
        contents=contents,
        config=generate_config,
    )

    # Process response
    if not response.candidates:
        if verbose:
            print("Error: No response candidates returned.")  # noqa: T201
            if hasattr(response, "prompt_feedback"):
                print(f"Feedback: {response.prompt_feedback}")  # noqa: T201
        return None

    # Track thoughts and final images
    thought_count = 0
    final_image_data = None
    final_mime_type = None
    final_signature = None

    # Determine output directory
    if output_dir is None:
        output_dir = Path.cwd()

    # Process all parts in response
    for part in response.candidates[0].content.parts:
        # Check if this is a thought (intermediate reasoning step)
        is_thought = hasattr(part, "thought") and part.thought

        if is_thought:
            thought_count += 1
            if verbose:
                print(f"\n[Thought {thought_count}]")  # noqa: T201

            # Handle thought text
            if part.text is not None and verbose:
                print(f"Reasoning: {part.text}")  # noqa: T201

            # Handle thought image
            if part.inline_data is not None and save_thoughts:
                thought_data = part.inline_data.data
                thought_mime = part.inline_data.mime_type
                thought_ext = get_file_extension(thought_mime)

                # Save thought image
                if output_path:
                    thought_path = (
                        output_dir
                        / f"{output_path.stem}_thought{thought_count}{thought_ext}"
                    )
                else:
                    timestamp = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
                    thought_path = (
                        output_dir / f"thought{thought_count}_{timestamp}{thought_ext}"
                    )

                thought_path.parent.mkdir(parents=True, exist_ok=True)
                with open(thought_path, "wb") as f:
                    f.write(thought_data)

                if verbose:
                    print(f"Thought image {thought_count} saved to: {thought_path}")  # noqa: T201

        # Non-thought content (final output)
        elif part.inline_data is not None:
            # Final image
            final_image_data = part.inline_data.data
            final_mime_type = part.inline_data.mime_type

            # Extract thought signature if available
            if hasattr(part, "thought_signature") and part.thought_signature:
                final_signature = part.thought_signature
                if verbose:
                    print(f"\n[Thought Signature]: {final_signature[:100]}...")  # noqa: T201

        elif part.text is not None and verbose:
            # Final text response
            print(f"\nModel response: {part.text}")  # noqa: T201

            # Extract thought signature from text part if available
            if hasattr(part, "thought_signature") and part.thought_signature:
                final_signature = part.thought_signature
                if verbose:
                    print(f"[Thought Signature]: {final_signature[:100]}...")  # noqa: T201

    # Save final image
    if final_image_data is not None:
        # Determine output filename
        if output_path is None:
            timestamp = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
            ext = get_file_extension(final_mime_type or "image/png")
            prefix = "draft_" if is_draft else "generated_"
            output_path = output_dir / f"{prefix}{timestamp}{ext}"
        elif not output_path.is_absolute():
            output_path = output_dir / output_path

        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write image
        with open(output_path, "wb") as f:
            f.write(final_image_data)

        if verbose:
            if thought_count > 0:
                print(f"\nProcessed {thought_count} thought step(s)")  # noqa: T201
            print(f"Final image saved to: {output_path}")  # noqa: T201

        # Optionally save thought signature to sidecar file
        if final_signature and verbose:
            sig_path = output_path.with_suffix(".signature.bin")
            with open(sig_path, "wb") as f:
                if isinstance(final_signature, bytes):
                    f.write(final_signature)
                else:
                    f.write(str(final_signature).encode())
            print(f"Thought signature saved to: {sig_path}")  # noqa: T201

        return output_path

    if verbose:
        print("Error: No image data in response.")  # noqa: T201
    return None


def generate_story_sequence(
    base_prompt: str,
    num_parts: int,
    model_key: ModelKey = DEFAULT_MODEL,
    output_prefix: Path | None = None,
    output_dir: Path | None = None,
    aspect_ratio: AspectRatio | None = None,
    image_size: ImageSize | None = None,
    verbose: bool = False,
) -> list[Path]:
    """Generate a multi-part story sequence using conversational refinement.

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

    Returns:
        List of paths to generated images.

    Raises:
        ValueError: If num_parts < 1.

    """
    if num_parts < 1:
        msg = "Number of story parts must be at least 1"
        raise ValueError(msg)

    if output_dir is None:
        output_dir = Path.cwd()

    if output_prefix is None:
        timestamp = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
        output_prefix = Path(f"story_{timestamp}")

    generated_images: list[Path] = []
    previous_image_path: Path | None = None

    if verbose:
        print(f"Generating {num_parts}-part story sequence...")  # noqa: T201
        print(f"Base prompt: {base_prompt}\n")  # noqa: T201

    for part_num in range(1, num_parts + 1):
        if verbose:
            print(f"\n{'=' * 60}")  # noqa: T201
            print(f"PART {part_num}/{num_parts}")  # noqa: T201
            print(f"{'=' * 60}")  # noqa: T201

        # Build prompt for this part
        if part_num == 1:
            prompt = (
                f"{base_prompt}\n\n"
                f"This is part 1 of {num_parts}. Create the opening scene that "
                "establishes the context and visual style for the entire sequence."
            )
        elif part_num == num_parts:
            prompt = (
                f"This is part {part_num} of {num_parts}, the final scene. "
                "Building on the previous image, create a concluding scene that "
                "resolves the narrative. Maintain visual consistency with the "
                "established style."
            )
        else:
            prompt = (
                f"This is part {part_num} of {num_parts}. Building on the previous "
                "image, advance the narrative while maintaining visual consistency "
                "with the established style."
            )

        # Build output path
        output_path = Path(f"{output_prefix.stem}_part{part_num}.png")

        # Build reference images list
        reference_images = [previous_image_path] if previous_image_path else None

        if verbose:
            print(f"Prompt: {prompt[:100]}...")  # noqa: T201

        # Generate this part
        result = generate_image(
            prompt=prompt,
            model_key=model_key,
            reference_images=reference_images,
            output_path=output_path,
            output_dir=output_dir,
            aspect_ratio=aspect_ratio,
            image_size=image_size,
            use_search=False,
            save_thoughts=False,
            verbose=verbose,
        )

        if result:
            generated_images.append(result)
            previous_image_path = result
            if verbose:
                print(f"Part {part_num} complete: {result}")  # noqa: T201
        else:
            if verbose:
                print(f"Failed to generate part {part_num}")  # noqa: T201
            break

    if verbose:
        print(f"\n{'=' * 60}")  # noqa: T201
        print(  # noqa: T201
            f"Story sequence complete: {len(generated_images)}/{num_parts} parts generated"
        )
        print(f"{'=' * 60}\n")  # noqa: T201

        for i, path in enumerate(generated_images, 1):
            print(f"  Part {i}: {path}")  # noqa: T201

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
) -> Path | None:
    """Finalize a draft image by regenerating at higher resolution.

    Args:
        draft_path: Path to the draft image.
        prompt: Optional refinement prompt. If not provided, uses a
            default upscaling prompt.
        model_key: Model to use.
        output_path: Output path for the final image.
        output_dir: Output directory.
        aspect_ratio: Aspect ratio (default: "16:9").
        image_size: Target resolution (default: "2K").
        verbose: Show detailed process.

    Returns:
        Path to the finalized image, or None on failure.

    Raises:
        FileNotFoundError: If the draft image doesn't exist.

    """
    if not draft_path.exists():
        msg = f"Draft image not found: {draft_path}"
        raise FileNotFoundError(msg)

    # Determine final resolution
    final_size = image_size if image_size else "2K"
    final_aspect = aspect_ratio if aspect_ratio else "16:9"

    if verbose:
        print(f"Finalizing draft image: {draft_path}")  # noqa: T201
        print(f"Target resolution: {final_size} ({final_aspect})")  # noqa: T201

    # Use provided prompt or default upscaling prompt
    final_prompt = prompt or (
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
    )

    if result and verbose:
        print(f"\n{'=' * 60}")  # noqa: T201
        print("Finalization complete!")  # noqa: T201
        print(f"Draft: {draft_path}")  # noqa: T201
        print(f"Final ({final_size}): {result}")  # noqa: T201
        print(f"{'=' * 60}")  # noqa: T201

    return result
