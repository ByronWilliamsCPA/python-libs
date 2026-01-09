# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-01-09

### Added

- OpenSSF-required files: LICENSE, SECURITY.md, CONTRIBUTING.md, CHANGELOG.md
- `exceptions.py` module with custom exception hierarchy
- `client.py` module with `GeminiClient` class and retry logic using tenacity
- `io.py` module with magic byte format detection
- `registry.py` module for PROMPTS.md documentation
- `response_parser.py` module for API response handling
- Structured logging with structlog (replaces print statements)
- `--no-document` CLI flag to disable PROMPTS.md logging
- `--resume` flag for story sequence generation (skips existing parts)
- JSON sidecar metadata files for generated images
- Python 3.10 compatibility (replaced `datetime.UTC` with `timezone.utc`)

### Changed

- Refactored `generator.py` into smaller, focused modules
- Improved error handling with specific exception types
- Output paths now honor absolute paths (no forced `output/` prefix)
- API key loading now uses python-dotenv for robust .env handling

### Fixed

- JPEG/PNG format mismatch from Gemini API (magic byte detection)
- Story mode now resumes from last completed part instead of regenerating

## [0.1.0] - 2024-12-15

### Added

- Initial release
- `generate_image()` function for text-to-image generation
- `generate_story_sequence()` function for multi-part stories
- `finalize_draft()` function for draft-to-final workflow
- CLI (`gemini-image` command)
- Support for Gemini 2.5 Flash and Gemini 3 Pro models
- Aspect ratio and resolution configuration
- Reference image support for editing
- Thinking mode with intermediate image visualization
- Draft mode for cost-effective iteration

[0.2.0]: https://github.com/ByronWilliamsCPA/python-libs/compare/gemini-image-v0.1.0...gemini-image-v0.2.0
[0.1.0]: https://github.com/ByronWilliamsCPA/python-libs/releases/tag/gemini-image-v0.1.0
