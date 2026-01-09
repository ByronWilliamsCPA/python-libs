#!/usr/bin/env python3
"""Validate gemini-image installation and configuration.

Usage:
    python scripts/validate_installation.py
    # or
    uv run python scripts/validate_installation.py
"""

from __future__ import annotations

import sys


def check_import() -> bool:
    """Check if the package can be imported."""
    print("Checking package import...", end=" ")
    try:
        import gemini_image  # noqa: F401

        print("OK")
        return True
    except ImportError as e:
        print(f"FAILED: {e}")
        return False


def check_exports() -> bool:
    """Check if all expected functions are exported."""
    print("Checking exports...", end=" ")
    try:
        from gemini_image import (
            finalize_draft,
            generate_batch,
            generate_image,
            generate_story_sequence,
        )

        exports = [generate_image, generate_story_sequence, generate_batch, finalize_draft]
        if all(callable(f) for f in exports):
            print("OK")
            return True
        print("FAILED: Some exports are not callable")
        return False
    except ImportError as e:
        print(f"FAILED: {e}")
        return False


def check_exceptions() -> bool:
    """Check if exception classes are available."""
    print("Checking exceptions...", end=" ")
    try:
        from gemini_image.exceptions import (
            APIError,
            ConfigurationError,
            ContentBlockedError,
            FileOperationError,
            FormatDetectionError,
            GeminiImageError,
            RateLimitError,
            ValidationError,
        )

        exceptions = [
            GeminiImageError,
            ConfigurationError,
            ValidationError,
            APIError,
            RateLimitError,
            ContentBlockedError,
            FileOperationError,
            FormatDetectionError,
        ]
        if all(issubclass(e, Exception) for e in exceptions):
            print("OK")
            return True
        print("FAILED: Some exceptions are not proper Exception subclasses")
        return False
    except ImportError as e:
        print(f"FAILED: {e}")
        return False


def check_api_key() -> bool:
    """Check if API key is configured."""
    print("Checking API key configuration...", end=" ")
    try:
        from gemini_image.client import get_api_key

        key = get_api_key()
        if key and len(key) > 10:
            # Key found and valid length - don't log any part of the key
            print("OK (API key configured)")
            return True
        print("FAILED: API key too short or empty")
        return False
    except Exception as e:
        print(f"FAILED: {e}")
        return False


def check_cli() -> bool:
    """Check if CLI is accessible."""
    print("Checking CLI entry point...", end=" ")
    try:
        from gemini_image.cli import main

        if callable(main):
            print("OK")
            return True
        print("FAILED: CLI main is not callable")
        return False
    except ImportError as e:
        print(f"FAILED: {e}")
        return False


def check_models() -> bool:
    """Check if model configurations are valid."""
    print("Checking model configurations...", end=" ")
    try:
        from gemini_image.models import MODELS

        if "flash" in MODELS and "pro" in MODELS:
            print(f"OK (models: {', '.join(MODELS.keys())})")
            return True
        print("FAILED: Expected 'flash' and 'pro' models")
        return False
    except ImportError as e:
        print(f"FAILED: {e}")
        return False


def check_io_functions() -> bool:
    """Check if I/O functions are available."""
    print("Checking I/O functions...", end=" ")
    try:
        from gemini_image.io import (
            detect_image_format,
            save_image,
            validate_image_file,
        )

        if all(callable(f) for f in [detect_image_format, save_image, validate_image_file]):
            print("OK")
            return True
        print("FAILED: Some I/O functions are not callable")
        return False
    except ImportError as e:
        print(f"FAILED: {e}")
        return False


def main() -> int:
    """Run all validation checks."""
    print("=" * 50)
    print("Gemini Image Installation Validation")
    print("=" * 50)
    print()

    checks = [
        ("Package Import", check_import),
        ("Function Exports", check_exports),
        ("Exception Classes", check_exceptions),
        ("CLI Entry Point", check_cli),
        ("Model Configurations", check_models),
        ("I/O Functions", check_io_functions),
        ("API Key", check_api_key),  # Last since it's optional for basic install
    ]

    results: list[tuple[str, bool]] = []
    for name, check_fn in checks:
        result = check_fn()
        results.append((name, result))

    print()
    print("=" * 50)
    print("Summary")
    print("=" * 50)

    passed = sum(1 for _, ok in results if ok)
    total = len(results)

    for name, ok in results:
        status = "PASS" if ok else "FAIL"
        print(f"  {name}: {status}")

    print()
    print(f"Result: {passed}/{total} checks passed")

    # API key is optional for installation validation
    core_passed = all(ok for name, ok in results if name != "API Key")

    if core_passed:
        print()
        if not results[-1][1]:  # API key failed
            print("Note: API key not configured. Set GEMINI_API_KEY to enable generation.")
        print("Installation is valid!")
        return 0
    else:
        print()
        print("Installation has issues. Please check the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
