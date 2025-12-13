"""CLI commands for IP group management.

Provides command-line interface for syncing IP groups to Cloudflare.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from cloudflare_api.ip_groups.manager import IPGroupManager


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for CLI output.

    Args:
        verbose: Enable debug logging.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def cmd_sync(args: argparse.Namespace) -> int:
    """Sync IP groups to Cloudflare.

    Args:
        args: Parsed command line arguments.

    Returns:
        Exit code (0 for success).
    """
    manager = IPGroupManager.from_config(args.config)

    if args.group:
        results = [manager.sync_group(args.group, dry_run=args.dry_run)]
    else:
        results = manager.sync_all(dry_run=args.dry_run)

    # Print results
    for result in results:
        if result.error:
            print(f"❌ {result.group_name}: {result.error}")
        elif result.unchanged:
            print(f"✓ {result.group_name}: No changes ({result.ips_count} IPs)")
        else:
            print(
                f"✓ {result.group_name}: Synced {result.ips_count} IPs "
                f"(+{result.added}, -{result.removed}) "
                f"in {result.duration_seconds:.1f}s"
            )

    # Return error if any failed
    failed = sum(1 for r in results if r.error)
    return 1 if failed > 0 else 0


def cmd_preview(args: argparse.Namespace) -> int:
    """Preview changes for an IP group.

    Args:
        args: Parsed command line arguments.

    Returns:
        Exit code.
    """
    manager = IPGroupManager.from_config(args.config)
    preview = manager.preview_group(args.group)

    if args.json:
        print(json.dumps(preview, indent=2))
    else:
        print(f"\nGroup: {preview['group_name']}")
        print(f"Cloudflare List: {preview['cloudflare_list_name']}")
        print(f"Current IPs: {preview['current_count']}")
        print(f"New IPs: {preview['new_count']}")

        if preview["to_add"]:
            print(f"\n📥 To Add ({len(preview['to_add'])}):")
            for ip in preview["to_add"][:10]:
                print(f"  + {ip}")
            if len(preview["to_add"]) > 10:
                print(f"  ... and {len(preview['to_add']) - 10} more")

        if preview["to_remove"]:
            print(f"\n📤 To Remove ({len(preview['to_remove'])}):")
            for ip in preview["to_remove"][:10]:
                print(f"  - {ip}")
            if len(preview["to_remove"]) > 10:
                print(f"  ... and {len(preview['to_remove']) - 10} more")

        if not preview["will_change"]:
            print("\n✓ No changes needed")

    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """List all configured IP groups.

    Args:
        args: Parsed command line arguments.

    Returns:
        Exit code.
    """
    manager = IPGroupManager.from_config(args.config)
    groups = manager.list_groups()

    if args.json:
        print(json.dumps(groups, indent=2))
    else:
        print("\nConfigured IP Groups:")
        print("-" * 60)
        for group in groups:
            status = "✓" if group["enabled"] else "✗"
            sources = ", ".join(group["source_types"])
            print(f"{status} {group['name']}")
            print(f"   List: {group['cloudflare_list_name']}")
            print(f"   Sources: {sources}")
            if group["description"]:
                print(f"   Desc: {group['description']}")
            print()

    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    """Fetch and display IPs for a group (without syncing).

    Args:
        args: Parsed command line arguments.

    Returns:
        Exit code.
    """
    manager = IPGroupManager.from_config(args.config)

    group = manager._get_group(args.group)
    ips = manager.fetch_group_ips(group, use_cache=not args.no_cache)

    if args.json:
        print(json.dumps({"group": args.group, "ips": ips}, indent=2))
    else:
        print(f"\nFetched {len(ips)} IPs for '{args.group}':")
        for ip in ips:
            print(f"  {ip}")

    return 0


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point.

    Args:
        argv: Command line arguments.

    Returns:
        Exit code.
    """
    parser = argparse.ArgumentParser(
        description="Manage IP range groups for Cloudflare",
        prog="cloudflare-ip-groups",
    )
    parser.add_argument(
        "-c", "--config",
        type=Path,
        default=Path("ip_groups.yaml"),
        help="Path to config file (default: ip_groups.yaml)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Sync command
    sync_parser = subparsers.add_parser("sync", help="Sync IP groups to Cloudflare")
    sync_parser.add_argument(
        "-g", "--group",
        help="Specific group to sync (default: all enabled groups)",
    )
    sync_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without applying",
    )
    sync_parser.set_defaults(func=cmd_sync)

    # Preview command
    preview_parser = subparsers.add_parser("preview", help="Preview changes for a group")
    preview_parser.add_argument("group", help="Group name to preview")
    preview_parser.add_argument("--json", action="store_true", help="Output as JSON")
    preview_parser.set_defaults(func=cmd_preview)

    # List command
    list_parser = subparsers.add_parser("list", help="List configured groups")
    list_parser.add_argument("--json", action="store_true", help="Output as JSON")
    list_parser.set_defaults(func=cmd_list)

    # Fetch command
    fetch_parser = subparsers.add_parser("fetch", help="Fetch IPs for a group")
    fetch_parser.add_argument("group", help="Group name to fetch")
    fetch_parser.add_argument("--json", action="store_true", help="Output as JSON")
    fetch_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass cache and fetch fresh data",
    )
    fetch_parser.set_defaults(func=cmd_fetch)

    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        logging.exception("Unexpected error")
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
