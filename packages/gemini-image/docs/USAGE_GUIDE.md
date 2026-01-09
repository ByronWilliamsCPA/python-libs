# Gemini Image Usage Guide

A comprehensive guide to using the gemini-image library for AI-powered image generation.

## Table of Contents

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Basic Usage](#basic-usage)
4. [Advanced Features](#advanced-features)
5. [Workflow Patterns](#workflow-patterns)
6. [Troubleshooting](#troubleshooting)

## Installation

### Using uv (recommended)

```bash
uv add byronwilliamscpa-gemini-image
```

### Using pip

```bash
pip install byronwilliamscpa-gemini-image
```

## Configuration

### API Key Setup

The library requires a Google Gemini API key. You can obtain one from the
[Google AI Studio](https://makersuite.google.com/app/apikey).

**Option 1: Environment variable**

```bash
export GEMINI_API_KEY='your-api-key-here'
```

**Option 2: .env file**

Create a `.env` file in your project directory:

```bash
GEMINI_API_KEY=your-api-key-here
```

The library automatically loads `.env` files using python-dotenv.

## Basic Usage

### Python API

```python
from gemini_image import generate_image

# Simple text-to-image generation
result = generate_image("A futuristic city at sunset")
print(f"Image saved to: {result}")
```

### Command Line

```bash
# Basic generation
gemini-image "A serene mountain landscape at dawn"

# With custom output path
gemini-image "A technical blueprint" -o blueprint.png
```

## Advanced Features

### Model Selection

Two models are available:

| Key | Model | Best For |
|-----|-------|----------|
| `flash` | Gemini 2.5 Flash | Fast iterations, drafts |
| `pro` | Gemini 3 Pro | High quality, text rendering, 4K |

```python
# Using Flash model for speed
result = generate_image("Quick sketch", model_key="flash")

# Using Pro model for quality (default)
result = generate_image("Detailed illustration", model_key="pro")
```

### Resolution Control

The Pro model supports multiple resolutions:

| Size | 16:9 Dimensions | Cost Factor |
|------|-----------------|-------------|
| 1K | ~1408 x 768 | 1x (draft) |
| 2K | 2752 x 1536 | 2x |
| 4K | 5504 x 3072 | 4x |

```python
# Generate at 4K resolution
result = generate_image(
    "A detailed landscape",
    image_size="4K",
    aspect_ratio="16:9",
)
```

### Aspect Ratios

Supported aspect ratios:

- `1:1` - Square (social media, profile images)
- `3:4` - Portrait (documents, posters)
- `4:3` - Standard landscape (presentations)
- `9:16` - Vertical/mobile (stories, mobile apps)
- `16:9` - Widescreen (documents, videos)

```python
# Square image for social media
result = generate_image("Profile avatar", aspect_ratio="1:1")

# Vertical for mobile
result = generate_image("Mobile wallpaper", aspect_ratio="9:16")
```

### Reference-Based Editing

Modify existing images with prompts:

```python
from pathlib import Path

# Edit an existing image
edited = generate_image(
    "Make the sky more dramatic",
    reference_images=[Path("original.png")],
)
```

CLI:

```bash
gemini-image "Add more clouds" -r original.png -o edited.png
```

### Multi-Part Story Sequences

Generate a series of related images with visual continuity:

```python
from gemini_image import generate_story_sequence

# Generate a 4-part story
images = generate_story_sequence(
    "The evolution of a seed growing into a tree",
    num_parts=4,
    aspect_ratio="16:9",
)

for i, path in enumerate(images, 1):
    print(f"Part {i}: {path}")
```

CLI:

```bash
# Generate story sequence
gemini-image "A day in the life of a city" --story-parts 4 -o city_story

# Resume interrupted sequence
gemini-image "Continue the story" --story-parts 6 -o city_story --resume
```

### Batch Processing

Process multiple prompts from a JSON file:

**prompts.json:**

```json
[
    {
        "prompt": "A sunrise over mountains",
        "aspect_ratio": "16:9",
        "image_size": "2K"
    },
    {
        "prompt": "A forest path in autumn",
        "model_key": "pro",
        "output_path": "forest.png"
    },
    {
        "prompt": "A city skyline at night",
        "aspect_ratio": "1:1"
    }
]
```

**Python:**

```python
import json
from pathlib import Path
from gemini_image import generate_batch

with open("prompts.json") as f:
    prompts = json.load(f)

results = generate_batch(
    prompts=prompts,
    output_dir=Path("./output"),
    show_progress=True,
)

for prompt, result in zip(prompts, results):
    if result:
        print(f"Generated: {result}")
    else:
        print(f"Failed: {prompt['prompt'][:30]}...")
```

**CLI:**

```bash
gemini-image --batch prompts.json -d ./output
```

### Batch Fields Reference

| Field | Type | Description |
|-------|------|-------------|
| `prompt` | str | Text description (required) |
| `output_path` | str | Specific output filename |
| `model_key` | str | "flash" or "pro" |
| `aspect_ratio` | str | "1:1", "3:4", "4:3", "9:16", "16:9" |
| `image_size` | str | "1K", "2K", "4K" |
| `reference_images` | list | Paths to reference images |

## Workflow Patterns

### Draft-Then-Finalize Workflow

Save ~75% on costs during iteration:

```python
from pathlib import Path
from gemini_image import generate_image, finalize_draft

# 1. Generate draft at 1K (fast, cheap)
draft = generate_image(
    "A technical architecture diagram",
    is_draft=True,
)

# 2. Review and iterate on draft
draft_v2 = generate_image(
    "Add more detail to the database section",
    reference_images=[draft],
    is_draft=True,
)

# 3. Finalize at higher resolution when satisfied
final = finalize_draft(
    draft_v2,
    image_size="2K",
)
```

CLI workflow:

```bash
# Draft mode
gemini-image "Technical blueprint" --draft-mode -o draft.png

# Iterate
gemini-image "Add annotations" -r draft.png --draft-mode -o draft_v2.png

# Finalize
gemini-image --finalize draft_v2.png --size 2K -o final.png
```

### PROMPTS.md Registry

Every generation is automatically logged to `PROMPTS.md`:

```markdown
## Generation Log

### 2026-01-09 14:30:22 - architecture_diagram.png
- **Prompt**: A technical architecture diagram showing microservices
- **Model**: pro
- **Size**: 2K
- **Aspect**: 16:9
```

**Disable for privacy:**

```python
result = generate_image("Private prompt", document=False)
```

```bash
gemini-image "Private prompt" --no-document -o private.png
```

### Metadata Sidecar Files

Each image can have a JSON metadata file:

```python
# Enable metadata file (default)
result = generate_image(
    "Test prompt",
    save_metadata_file=True,  # Creates result.json alongside result.png
)
```

The metadata file contains:

```json
{
    "prompt": "Test prompt",
    "model": "pro",
    "aspect_ratio": "16:9",
    "image_size": "2K",
    "created_at": "2026-01-09T14:30:22Z"
}
```

### Thinking Mode

Visualize the model's reasoning process:

```bash
gemini-image "Complex technical diagram" --save-thoughts --verbose
```

This saves intermediate thinking images alongside the final result.

## Troubleshooting

### Common Errors

**ConfigurationError: GEMINI_API_KEY not found**

```python
# Solution: Set the environment variable
import os
os.environ["GEMINI_API_KEY"] = "your-key"
```

**RateLimitError**

The library automatically retries with exponential backoff. If you still hit limits:

```python
import time

for prompt in prompts:
    try:
        result = generate_image(prompt)
    except RateLimitError:
        time.sleep(60)  # Wait before retrying
        result = generate_image(prompt)
```

**ContentBlockedError**

The prompt triggered safety filters. Try rephrasing:

```python
from gemini_image.exceptions import ContentBlockedError

try:
    result = generate_image("potentially sensitive prompt")
except ContentBlockedError:
    print("Prompt was blocked by safety filters. Try rephrasing.")
```

**FormatDetectionError**

The API returned an unknown image format:

```python
from gemini_image.exceptions import FormatDetectionError

try:
    result = generate_image("test")
except FormatDetectionError as e:
    print(f"Unknown format: {e}")
```

### Debug Logging

Enable verbose output for debugging:

```python
result = generate_image(
    "Test prompt",
    verbose=True,  # Shows detailed progress
)
```

CLI:

```bash
gemini-image "Test prompt" --verbose
```

### Checking Available Models

```bash
gemini-image --list-models
```

## Exception Reference

| Exception | Cause | Solution |
|-----------|-------|----------|
| `ConfigurationError` | Missing API key | Set GEMINI_API_KEY |
| `ValidationError` | Invalid parameters | Check model_key, aspect_ratio, etc. |
| `APIError` | API returned error | Check prompt, retry |
| `RateLimitError` | Too many requests | Wait and retry |
| `ContentBlockedError` | Safety filter triggered | Rephrase prompt |
| `FileOperationError` | File I/O error | Check permissions |
| `FormatDetectionError` | Unknown image format | Report bug |

## Best Practices

1. **Use draft mode** for iteration - save costs and time
2. **Be specific** in prompts - detailed prompts yield better results
3. **Use reference images** for consistent style
4. **Enable registry** for prompt history tracking
5. **Handle exceptions** gracefully in production code
6. **Use batch processing** for multiple generations
