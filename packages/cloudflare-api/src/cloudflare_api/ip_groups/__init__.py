"""IP Range Group management for Cloudflare.

Provides a system for defining, fetching, and syncing IP range groups
to Cloudflare IP lists for use in Access policies.

Example:
    ```python
    from cloudflare_api.ip_groups import IPGroupManager

    manager = IPGroupManager.from_config("ip_groups.yaml")
    manager.sync_all()  # Updates all Cloudflare lists
    ```
"""

from cloudflare_api.ip_groups.config import (
    IPGroupConfig,
    IPSourceConfig,
    SourceType,
    load_config,
)
from cloudflare_api.ip_groups.fetchers import (
    AWSIPFetcher,
    GitHubIPFetcher,
    GoogleCloudIPFetcher,
    IPFetcher,
    StaticIPFetcher,
    URLIPFetcher,
)
from cloudflare_api.ip_groups.manager import IPGroupManager

__all__ = [
    # Config
    "IPGroupConfig",
    "IPSourceConfig",
    "SourceType",
    "load_config",
    # Fetchers
    "IPFetcher",
    "StaticIPFetcher",
    "URLIPFetcher",
    "GitHubIPFetcher",
    "GoogleCloudIPFetcher",
    "AWSIPFetcher",
    # Manager
    "IPGroupManager",
]
