"""Command-line interface for Gemini image generation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from gemini_image.generator import (
    finalize_draft,
    generate_image,
    generate_story_sequence,
)
from gemini_image.models import ASPECT_RATIOS, DEFAULT_MODEL, IMAGE_SIZES, MODELS


def list_models() -> None:
    """Print available models."""
    print("Available models:\n")
    for key, config in MODELS.items():
        print(f"  {key}:")
        print(f"    Name: {config['name']}")
        print(f"    ID: {config['id']}")
        print(f"    Description: {config['description']}")
        print()


def main() -> None:
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="Generate images using Google Gemini (Nano Banana / Nano Banana Pro)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single image generation
  %(prog)s "A serene mountain landscape at dawn"
  %(prog)s "A data governance diagram" -o governance.png

  # Draft-then-finalize workflow (cost-effective iteration)
  %(prog)s "A technical blueprint" --draft-mode -o draft.png
  %(prog)s "Adjust colors" -r draft.png --draft-mode -o draft_v2.png
  %(prog)s --finalize draft_v2.png --size 2K -o final.png

  # Image editing with reference
  %(prog)s "Make the building taller" -r blueprint.png
  %(prog)s "Refine this architectural drawing" -r img1.png -r img2.png

  # Advanced options
  %(prog)s "A landscape" --aspect 16:9 --size 4K
  %(prog)s "Current weather in Tokyo" --search
  %(prog)s "Complex blueprint design" --save-thoughts --verbose

  # Multi-part story generation (automatic continuity)
  %(prog)s "A 3-part journey through data governance" --story-parts 3 -o journey
  %(prog)s "Evolution of a data platform" --story-parts 4 --aspect 16:9 --size 2K -o evolution
        """,
    )

    parser.add_argument(
        "prompt",
        nargs="?",
        help="Text prompt describing the image to generate",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output file path (default: generated_TIMESTAMP.png)",
    )

    parser.add_argument(
        "-d",
        "--output-dir",
        type=Path,
        help="Output directory (default: current directory)",
    )

    parser.add_argument(
        "-m",
        "--model",
        choices=list(MODELS.keys()),
        default=DEFAULT_MODEL,
        help=f"Model to use (default: {DEFAULT_MODEL})",
    )

    parser.add_argument(
        "-r",
        "--reference",
        type=Path,
        action="append",
        dest="references",
        help="Reference image(s) for editing or style (can be used multiple times)",
    )

    parser.add_argument(
        "--aspect",
        choices=ASPECT_RATIOS,
        help="Aspect ratio (pro model only): 1:1, 3:4, 4:3, 9:16, 16:9",
    )

    parser.add_argument(
        "--size",
        choices=IMAGE_SIZES,
        help="Image size (pro model only): 1K, 2K, 4K",
    )

    parser.add_argument(
        "--search",
        action="store_true",
        help="Enable Google Search grounding for real-time data (pro model only)",
    )

    parser.add_argument(
        "--save-thoughts",
        action="store_true",
        help="Save intermediate thought images (pro model only)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed thinking process and save thought signatures",
    )

    parser.add_argument(
        "--story-parts",
        type=int,
        metavar="N",
        help="Generate a multi-part story with N parts (uses previous image as reference)",
    )

    parser.add_argument(
        "--draft-mode",
        action="store_true",
        help="Generate at 1K resolution for faster, lower-cost iteration",
    )

    parser.add_argument(
        "--finalize",
        type=Path,
        metavar="DRAFT_IMAGE",
        help="Finalize a draft image by regenerating at higher resolution (2K default)",
    )

    parser.add_argument(
        "--list-models",
        action="store_true",
        help="List available models and exit",
    )

    args = parser.parse_args()

    if args.list_models:
        list_models()
        return

    # Finalize mode
    if args.finalize:
        try:
            result = finalize_draft(
                draft_path=args.finalize,
                prompt=args.prompt,
                model_key=args.model,
                output_path=args.output,
                output_dir=args.output_dir,
                aspect_ratio=args.aspect,
                image_size=args.size,
                verbose=args.verbose,
            )
            sys.exit(0 if result else 1)
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)

    if not args.prompt:
        parser.print_help()
        sys.exit(1)

    # Story sequence mode
    if args.story_parts:
        if args.story_parts < 2:
            print("Error: Story must have at least 2 parts")
            sys.exit(1)

        results = generate_story_sequence(
            base_prompt=args.prompt,
            num_parts=args.story_parts,
            model_key=args.model,
            output_prefix=args.output,
            output_dir=args.output_dir,
            aspect_ratio=args.aspect,
            image_size=args.size,
            verbose=args.verbose,
        )

        sys.exit(0 if len(results) == args.story_parts else 1)

    # Single image mode
    try:
        result = generate_image(
            prompt=args.prompt,
            model_key=args.model,
            reference_images=args.references,
            output_path=args.output,
            output_dir=args.output_dir,
            aspect_ratio=args.aspect,
            image_size=args.size,
            use_search=args.search,
            save_thoughts=args.save_thoughts,
            verbose=args.verbose,
            is_draft=args.draft_mode,
        )

        if result and args.draft_mode:
            print(f"\n{'=' * 60}")
            print("Draft complete! To finalize at higher resolution:")
            print(f"  gemini-image --finalize {result} --size 2K")
            print(f"{'=' * 60}")

        sys.exit(0 if result else 1)

    except (ValueError, ImportError) as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
