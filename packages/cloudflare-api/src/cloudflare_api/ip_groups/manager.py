"""IP Group Manager for syncing IP ranges to Cloudflare.

Orchestrates fetching IPs from various sources and syncing to Cloudflare lists.
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cloudflare_api.client import CloudflareAPIClient
from cloudflare_api.ip_groups.config import (
    IPGroupConfig,
    IPGroupsConfig,
    IPSourceConfig,
    load_config,
)
from cloudflare_api.ip_groups.fetchers import get_fetcher

logger = logging.getLogger(__name__)


@dataclass
class SyncResult:
    """Result of syncing an IP group.

    Attributes:
        group_name: Name of the IP group
        cloudflare_list_name: Cloudflare list name
        cloudflare_list_id: Cloudflare list ID
        ips_count: Number of IPs synced
        added: Number of IPs added
        removed: Number of IPs removed
        unchanged: Whether the list was unchanged
        error: Error message if sync failed
        duration_seconds: Time taken to sync
    """

    group_name: str
    cloudflare_list_name: str
    cloudflare_list_id: str | None = None
    ips_count: int = 0
    added: int = 0
    removed: int = 0
    unchanged: bool = False
    error: str | None = None
    duration_seconds: float = 0.0


@dataclass
class IPCache:
    """Cache for fetched IP ranges.

    Attributes:
        ips: Cached IP addresses
        fetched_at: When the IPs were fetched
        source_hash: Hash of the source config for invalidation
    """

    ips: list[str] = field(default_factory=list)
    fetched_at: datetime = field(default_factory=datetime.now)
    source_hash: str = ""


class IPGroupManager:
    """Manager for IP range groups.

    Handles fetching IPs from various sources and syncing them to Cloudflare.

    Example:
        ```python
        manager = IPGroupManager.from_config("ip_groups.yaml")

        # Sync all groups
        results = manager.sync_all()

        # Sync a specific group
        result = manager.sync_group("github-actions")

        # Preview changes without applying
        preview = manager.preview_group("home-network")
        ```
    """

    def __init__(
        self,
        config: IPGroupsConfig,
        client: CloudflareAPIClient | None = None,
    ) -> None:
        """Initialize the IP Group Manager.

        Args:
            config: IP groups configuration.
            client: Optional Cloudflare client. If not provided, creates one.
        """
        self.config = config
        self._client = client
        self._cache: dict[str, IPCache] = {}

    @classmethod
    def from_config(
        cls,
        config_path: str | Path,
        client: CloudflareAPIClient | None = None,
    ) -> "IPGroupManager":
        """Create a manager from a config file.

        Args:
            config_path: Path to the YAML config file.
            client: Optional Cloudflare client.

        Returns:
            Configured IPGroupManager.
        """
        config = load_config(config_path)
        return cls(config, client)

    @property
    def client(self) -> CloudflareAPIClient:
        """Get or create the Cloudflare client."""
        if self._client is None:
            self._client = CloudflareAPIClient()
        return self._client

    def _get_source_hash(self, source: IPSourceConfig) -> str:
        """Get a hash of the source config for cache invalidation.

        Args:
            source: Source configuration.

        Returns:
            Hash string.
        """
        config_str = json.dumps(source.model_dump(), sort_keys=True)
        # MD5 used only for cache key generation, not security purposes
        return hashlib.md5(config_str.encode(), usedforsecurity=False).hexdigest()[:8]

    def _is_cache_valid(self, cache: IPCache, source: IPSourceConfig) -> bool:
        """Check if cached IPs are still valid.

        Args:
            cache: Cached data.
            source: Source configuration.

        Returns:
            True if cache is valid.
        """
        # Check if source config changed
        if cache.source_hash != self._get_source_hash(source):
            return False

        # Check TTL
        ttl = timedelta(seconds=self.config.cache_ttl_seconds)
        return datetime.now(tz=timezone.utc) - cache.fetched_at <= ttl

    def fetch_source_ips(
        self,
        source: IPSourceConfig,
        use_cache: bool = True,
    ) -> list[str]:
        """Fetch IPs from a single source.

        Args:
            source: Source configuration.
            use_cache: Whether to use cached results.

        Returns:
            List of IP addresses.
        """
        cache_key = self._get_source_hash(source)

        # Check cache
        if use_cache and cache_key in self._cache:
            cache = self._cache[cache_key]
            if self._is_cache_valid(cache, source):
                logger.debug("Using cached IPs for %s", source.type.value)
                return cache.ips

        # Fetch from source
        fetcher = get_fetcher(source.type)
        ips = fetcher.fetch(source)

        # Update cache
        self._cache[cache_key] = IPCache(
            ips=ips,
            fetched_at=datetime.now(tz=timezone.utc),
            source_hash=self._get_source_hash(source),
        )

        return ips

    def fetch_group_ips(
        self,
        group: IPGroupConfig,
        use_cache: bool = True,
    ) -> list[str]:
        """Fetch all IPs for a group from all sources.

        Args:
            group: Group configuration.
            use_cache: Whether to use cached results.

        Returns:
            Deduplicated list of IP addresses.
        """
        all_ips: set[str] = set()

        for source in group.sources:
            try:
                ips = self.fetch_source_ips(source, use_cache)
                all_ips.update(ips)
            except Exception:
                logger.exception(
                    "Failed to fetch IPs from %s source",
                    source.type.value,
                )
                raise

        logger.info(
            "Fetched %d unique IPs for group '%s' from %d sources",
            len(all_ips),
            group.name,
            len(group.sources),
        )

        return sorted(all_ips)

    def preview_group(self, group_name: str) -> dict[str, Any]:
        """Preview what would change for a group without applying.

        Args:
            group_name: Name of the group to preview.

        Returns:
            Dict with current and new IPs, and diff.

        Raises:
            ValueError: If group not found.
        """
        group = self._get_group(group_name)

        # Fetch new IPs
        new_ips = set(self.fetch_group_ips(group))

        # Get current IPs from Cloudflare
        list_name = self._get_cloudflare_list_name(group)
        current_ips: set[str] = set()

        existing_list = self.client.get_ip_list_by_name(list_name)
        if existing_list:
            items = self.client.get_ip_list_items(existing_list.id)
            current_ips = {item.ip for item in items}

        # Calculate diff
        to_add = new_ips - current_ips
        to_remove = current_ips - new_ips
        unchanged = current_ips & new_ips

        return {
            "group_name": group.name,
            "cloudflare_list_name": list_name,
            "current_count": len(current_ips),
            "new_count": len(new_ips),
            "to_add": sorted(to_add),
            "to_remove": sorted(to_remove),
            "unchanged_count": len(unchanged),
            "will_change": bool(to_add or to_remove),
        }

    def sync_group(self, group_name: str, dry_run: bool = False) -> SyncResult:
        """Sync a single IP group to Cloudflare.

        Args:
            group_name: Name of the group to sync.
            dry_run: If True, preview without applying changes.

        Returns:
            SyncResult with details of the operation.

        Raises:
            ValueError: If group not found or disabled.
        """
        start_time = time.time()
        group = self._get_group(group_name)

        if not group.enabled:
            return SyncResult(
                group_name=group.name,
                cloudflare_list_name=self._get_cloudflare_list_name(group),
                error="Group is disabled",
            )

        list_name = self._get_cloudflare_list_name(group)

        try:
            # Fetch new IPs
            new_ips = self.fetch_group_ips(group)

            if dry_run:
                preview = self.preview_group(group_name)
                return SyncResult(
                    group_name=group.name,
                    cloudflare_list_name=list_name,
                    ips_count=len(new_ips),
                    added=len(preview["to_add"]),
                    removed=len(preview["to_remove"]),
                    unchanged=not preview["will_change"],
                    duration_seconds=time.time() - start_time,
                )

            # Ensure list exists
            cf_list = self.client.ensure_ip_list(
                name=list_name,
                kind="ip",
                description=group.description or f"Managed IP group: {group.name}",
            )

            # Get current items for diff calculation
            current_items = self.client.get_ip_list_items(cf_list.id)
            current_ips = {item.ip for item in current_items}
            new_ip_set = set(new_ips)

            added = len(new_ip_set - current_ips)
            removed = len(current_ips - new_ip_set)

            if added == 0 and removed == 0:
                logger.info("No changes needed for '%s'", group.name)
                return SyncResult(
                    group_name=group.name,
                    cloudflare_list_name=list_name,
                    cloudflare_list_id=cf_list.id,
                    ips_count=len(new_ips),
                    unchanged=True,
                    duration_seconds=time.time() - start_time,
                )

            # Sync the list
            comments = dict.fromkeys(new_ips, f"Managed by {group.name}")
            self.client.sync_ip_list(cf_list.id, new_ips, comments)

            logger.info(
                "Synced '%s' to Cloudflare: %d IPs (+%d, -%d)",
                group.name,
                len(new_ips),
                added,
                removed,
            )

            return SyncResult(
                group_name=group.name,
                cloudflare_list_name=list_name,
                cloudflare_list_id=cf_list.id,
                ips_count=len(new_ips),
                added=added,
                removed=removed,
                duration_seconds=time.time() - start_time,
            )

        except Exception:
            logger.exception("Failed to sync group '%s'", group.name)
            return SyncResult(
                group_name=group.name,
                cloudflare_list_name=list_name,
                error="Sync failed - see logs for details",
                duration_seconds=time.time() - start_time,
            )

    def sync_all(self, dry_run: bool = False) -> list[SyncResult]:
        """Sync all enabled IP groups to Cloudflare.

        Args:
            dry_run: If True, preview without applying changes.

        Returns:
            List of SyncResults for each group.
        """
        results = []

        for group in self.config.groups:
            if group.enabled:
                result = self.sync_group(group.name, dry_run=dry_run)
                results.append(result)
            else:
                logger.debug("Skipping disabled group: %s", group.name)

        # Log summary
        success = sum(1 for r in results if r.error is None)
        failed = sum(1 for r in results if r.error is not None)
        total_ips = sum(r.ips_count for r in results if r.error is None)

        logger.info(
            "Sync complete: %d groups succeeded, %d failed, %d total IPs",
            success,
            failed,
            total_ips,
        )

        return results

    def list_groups(self) -> list[dict[str, Any]]:
        """List all configured IP groups.

        Returns:
            List of group summaries.
        """
        return [
            {
                "name": group.name,
                "cloudflare_list_name": self._get_cloudflare_list_name(group),
                "description": group.description,
                "enabled": group.enabled,
                "sources_count": len(group.sources),
                "source_types": [s.type.value for s in group.sources],
                "tags": group.tags,
            }
            for group in self.config.groups
        ]

    def _get_group(self, group_name: str) -> IPGroupConfig:
        """Get a group by name.

        Args:
            group_name: Name of the group.

        Returns:
            Group configuration.

        Raises:
            ValueError: If group not found.
        """
        for group in self.config.groups:
            if group.name == group_name:
                return group

        available = [g.name for g in self.config.groups]
        msg = f"Group '{group_name}' not found. Available: {available}"
        raise ValueError(msg)

    def _get_cloudflare_list_name(self, group: IPGroupConfig) -> str:
        """Get the Cloudflare list name for a group.

        Args:
            group: Group configuration.

        Returns:
            Cloudflare list name with optional prefix.
        """
        prefix = self.config.cloudflare_list_prefix
        if prefix:
            return f"{prefix}{group.cloudflare_list_name}"
        return group.cloudflare_list_name

    def clear_cache(self) -> None:
        """Clear all cached IP data."""
        self._cache.clear()
        logger.info("Cleared IP cache")
