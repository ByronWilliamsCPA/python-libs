"""Cloudflare API client package.

Provides a high-level client for managing Cloudflare resources including
IP lists, firewall rules, and Access policies.

Example:
    ```python
    from cloudflare_api import CloudflareAPIClient

    client = CloudflareAPIClient()

    # List all IP lists
    lists = client.list_ip_lists()

    # Create and populate a list
    new_list = client.create_ip_list("blocked-ips", description="Bad actors")
    client.add_ip_list_items(new_list.id, [{"ip": "1.2.3.4", "comment": "Spam"}])
    ```

IP Groups Example:
    ```python
    from cloudflare_api.ip_groups import IPGroupManager

    manager = IPGroupManager.from_config("ip_groups.yaml")
    manager.sync_all()  # Updates all Cloudflare lists from configured sources
    ```
"""

from cloudflare_api.client import CloudflareAPIClient
from cloudflare_api.exceptions import (
    CloudflareAPIError,
    CloudflareAuthError,
    CloudflareBulkOperationError,
    CloudflareConflictError,
    CloudflareNotFoundError,
    CloudflareRateLimitError,
    CloudflareValidationError,
)
from cloudflare_api.models import (
    BulkOperation,
    BulkOperationStatus,
    IPList,
    IPListItem,
    IPListItemInput,
    ListKind,
)
from cloudflare_api.settings import (
    CloudflareAPISettings,
    get_cloudflare_api_settings,
    reset_settings,
)

__all__ = [
    "BulkOperation",
    "BulkOperationStatus",
    "CloudflareAPIClient",
    "CloudflareAPIError",
    "CloudflareAPISettings",
    "CloudflareAuthError",
    "CloudflareBulkOperationError",
    "CloudflareConflictError",
    "CloudflareNotFoundError",
    "CloudflareRateLimitError",
    "CloudflareValidationError",
    "IPList",
    "IPListItem",
    "IPListItemInput",
    "ListKind",
    "get_cloudflare_api_settings",
    "reset_settings",
]

__version__ = "0.1.0"
