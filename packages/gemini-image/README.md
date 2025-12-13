# Gemini Image Generation

A comprehensive image generation library built on Google's Gemini models (Nano Banana / Nano Banana Pro).

## Features

- **Text-to-image generation** with configurable resolution and aspect ratio
- **Reference-based editing** - modify existing images with prompts
- **Multi-part story generation** - sequential images with visual continuity
- **Draft-then-finalize workflow** - 75% cost reduction during iteration
- **Thinking mode** - visualize model reasoning with intermediate images

## Installation

```bash
# Using uv (recommended)
uv add byronwilliamscpa-gemini-image

# Using pip
pip install byronwilliamscpa-gemini-image
```

## Quick Start

### Set API Key

```bash
export GEMINI_API_KEY='your-api-key'
```

### Python API

```python
from gemini_image import generate_image, generate_story_sequence

# Basic text-to-image
result = generate_image("A futuristic city at sunset")
print(f"Image saved to: {result}")

# With resolution and aspect ratio
result = generate_image(
    "A technical blueprint",
    aspect_ratio="16:9",
    image_size="2K",
    verbose=True,
)

# Draft mode for iteration (1K resolution)
draft = generate_image(
    "A data governance diagram",
    is_draft=True,
)

# Reference-based editing
from pathlib import Path
edited = generate_image(
    "Make the title larger",
    reference_images=[Path("original.png")],
)

# Multi-part story sequence
from gemini_image import generate_story_sequence

images = generate_story_sequence(
    "A journey through data governance evolution",
    num_parts=3,
    aspect_ratio="16:9",
)
```

### Command Line

```bash
# Basic generation
gemini-image "A serene mountain landscape at dawn"

# With output path
gemini-image "A data governance diagram" -o governance.png

# Draft mode (faster, lower cost)
gemini-image "A technical blueprint" --draft-mode -o draft.png

# Finalize draft at higher resolution
gemini-image --finalize draft.png --size 2K -o final.png

# Reference-based editing
gemini-image "Make the building taller" -r blueprint.png

# Multi-part story
gemini-image "Evolution of a data platform" --story-parts 4 -o evolution

# Show thinking process
gemini-image "Complex blueprint design" --save-thoughts --verbose

# List available models
gemini-image --list-models
```

## Models

| Key | Model | Features |
|-----|-------|----------|
| `flash` | Gemini 2.5 Flash | Fast generation |
| `pro` | Gemini 3 Pro (default) | 4K, better text rendering, thinking mode |

## Resolution Options (Pro Model)

| Size | Dimensions (16:9) | Use Case |
|------|-------------------|----------|
| 1K | ~1408 x 768 | Draft mode, fast iteration |
| 2K | 2752 x 1536 | Standard documents |
| 4K | 5504 x 3072 | High-detail, large prints |

## Aspect Ratios

- `1:1` - Square
- `3:4` - Portrait
- `4:3` - Standard landscape
- `9:16` - Vertical/mobile
- `16:9` - Widescreen (default)

## Draft-Then-Finalize Workflow

Reduce costs by ~75% during iteration:

```bash
# 1. Generate draft at 1K
gemini-image "A technical blueprint" --draft-mode -o draft.png

# 2. Iterate on draft
gemini-image "Add more detail to the header" -r draft.png --draft-mode -o draft_v2.png

# 3. Finalize at 2K when satisfied
gemini-image --finalize draft_v2.png --size 2K -o final.png
```

## API Reference

### `generate_image()`

```python
def generate_image(
    prompt: str,
    model_key: ModelKey = "pro",
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
```

### `generate_story_sequence()`

```python
def generate_story_sequence(
    base_prompt: str,
    num_parts: int,
    model_key: ModelKey = "pro",
    output_prefix: Path | None = None,
    output_dir: Path | None = None,
    aspect_ratio: AspectRatio | None = None,
    image_size: ImageSize | None = None,
    verbose: bool = False,
) -> list[Path]:
```

### `finalize_draft()`

```python
def finalize_draft(
    draft_path: Path,
    prompt: str | None = None,
    model_key: ModelKey = "pro",
    output_path: Path | None = None,
    output_dir: Path | None = None,
    aspect_ratio: AspectRatio | None = None,
    image_size: ImageSize | None = None,
    verbose: bool = False,
) -> Path | None:
```

## License

MIT
