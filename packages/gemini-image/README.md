# Gemini Image Generation

A comprehensive image generation library built on Google's Gemini models (Nano Banana / Nano Banana Pro).

## Features

- **Text-to-image generation** with configurable resolution and aspect ratio
- **Reference-based editing** - modify existing images with prompts
- **Multi-part story generation** - sequential images with visual continuity
- **Draft-then-finalize workflow** - 75% cost reduction during iteration
- **Thinking mode** - visualize model reasoning with intermediate images
- **Batch processing** - generate multiple images from a JSON file
- **PROMPTS.md registry** - automatic documentation of all generations
- **Magic byte format detection** - automatic extension correction for API mismatches
- **Retry logic** - automatic retry with exponential backoff on transient failures

## Installation

```bash
# Using uv (recommended)
uv add byronwilliamscpa-gemini-image

# Using pip
pip install byronwilliamscpa-gemini-image
```

## Quick Start

### Set API Key

Create a `.env` file in your project directory:

```bash
GEMINI_API_KEY=your-api-key-here
```

Or set the environment variable:

```bash
export GEMINI_API_KEY='your-api-key'
```

### Python API

```python
from gemini_image import generate_image, generate_story_sequence, generate_batch

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
images = generate_story_sequence(
    "A journey through data governance evolution",
    num_parts=3,
    aspect_ratio="16:9",
)

# Batch processing
prompts = [
    {"prompt": "A sunset over mountains", "aspect_ratio": "16:9"},
    {"prompt": "A forest in autumn", "model_key": "pro"},
    {"prompt": "A city at night", "image_size": "2K"},
]
results = generate_batch(prompts, output_dir=Path("./images"))
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

# Resume interrupted story generation
gemini-image "Continue story" --story-parts 5 -o story --resume

# Batch processing from JSON file
gemini-image --batch prompts.json -d ./output

# Disable PROMPTS.md documentation (for privacy)
gemini-image "Private prompt" --no-document -o private.png

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
- `2:3` - Portrait (2x3)
- `3:2` - Landscape (3x2)
- `3:4` - Portrait
- `4:3` - Standard landscape
- `4:5` - Portrait (Instagram)
- `5:4` - Landscape (5x4)
- `9:16` - Vertical/mobile
- `16:9` - Widescreen (default)
- `21:9` - Ultra-wide/cinematic

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

## Batch Processing

Create a JSON file with prompts:

```json
[
    {"prompt": "A sunset over mountains", "aspect_ratio": "16:9"},
    {"prompt": "A forest in autumn", "model_key": "pro", "image_size": "2K"},
    {"prompt": "A city at night", "output_path": "city.png"}
]
```

Then process:

```bash
gemini-image --batch prompts.json -d ./output
```

Supported fields per prompt:

- `prompt` (required): Text description
- `output_path`: Specific output filename
- `model_key`: "flash" or "pro"
- `aspect_ratio`: Any supported ratio (see [Aspect Ratios](#aspect-ratios))
- `image_size`: "1K", "2K", "4K"
- `reference_images`: List of reference image paths (max 3 for flash, 14 for pro)

## PROMPTS.md Registry

Every generation is automatically logged to `PROMPTS.md` in the output directory:

```markdown
## Generation Log

### 2026-01-09 13:45:22 - generated_20260109_134522.jpg
- **Prompt**: A futuristic city at sunset
- **Model**: pro
- **Size**: 2K
- **Aspect**: 16:9
```

Disable with `--no-document` flag or `document=False` parameter.

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
    document: bool = True,           # Log to PROMPTS.md
    registry_path: Path | None = None,
    save_metadata_file: bool = True,  # Save JSON sidecar
) -> Path | None:
```

### `generate_batch()`

```python
def generate_batch(
    prompts: list[dict[str, object]],
    output_dir: Path | None = None,
    parallel: int = 1,
    resume: bool = True,
    document: bool = True,
    show_progress: bool = True,
) -> list[Path | None]:
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
    resume: bool = True,   # Skip existing parts
    document: bool = True,
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
    document: bool = True,
) -> Path | None:
```

## Exception Handling

```python
from gemini_image import (
    GeminiImageError,       # Base exception
    ConfigurationError,     # Missing API key
    ValidationError,        # Invalid parameters
    APIError,               # API errors
    RateLimitError,         # Rate limiting
    ContentBlockedError,    # Safety filter
    FileOperationError,     # File I/O errors
    FormatDetectionError,   # Unknown image format
)

try:
    result = generate_image("A sunset")
except RateLimitError:
    print("Rate limited, retry automatically handled")
except ContentBlockedError:
    print("Content blocked by safety filters")
except GeminiImageError as e:
    print(f"Generation failed: {e}")
```

## Development

```bash
# Clone and install
git clone https://github.com/ByronWilliamsCPA/python-libs.git
cd python-libs/packages/gemini-image
uv sync --all-extras

# Run tests
uv run pytest tests -v

# Run functional tests (requires API key)
uv run pytest tests/test_functional.py -v

# Lint
uv run ruff check src tests
```

## License

MIT
