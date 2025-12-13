"""Cloudflare API client for managing IP lists and other resources.

Uses the official Cloudflare Python SDK for API operations.
"""

import logging
import time
from typing import Any

from cloudflare import Cloudflare
from cloudflare._exceptions import (
    APIConnectionError,
    APIStatusError,
    AuthenticationError,
    BadRequestError,
    NotFoundError,
    RateLimitError,
)

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
from cloudflare_api.settings import CloudflareAPISettings, get_cloudflare_api_settings

logger = logging.getLogger(__name__)


class CloudflareAPIClient:
    """Client for Cloudflare API operations.

    Provides methods for managing IP lists, firewall rules, and other
    Cloudflare resources using the official SDK.

    Example:
        ```python
        client = CloudflareAPIClient()

        # List all IP lists
        lists = client.list_ip_lists()

        # Create a new list
        new_list = client.create_ip_list("blocked-ips", kind="ip")

        # Add items
        client.add_ip_list_items(new_list.id, [{"ip": "1.2.3.4"}])
        ```
    """

    def __init__(
        self,
        settings: CloudflareAPISettings | None = None,
    ) -> None:
        """Initialize the Cloudflare API client.

        Args:
            settings: Optional settings. If not provided, reads from environment.

        Raises:
            CloudflareAuthError: If authentication credentials are missing.
        """
        self.settings = settings or get_cloudflare_api_settings()
        self._client = Cloudflare(
            api_token=self.settings.get_token_value(),
        )
        self._account_id = self.settings.cloudflare_account_id

        logger.info(
            "Initialized Cloudflare API client for account %s",
            self._account_id[:8] + "...",
        )

    def _handle_api_error(self, error: Exception) -> None:
        """Convert SDK exceptions to our custom exceptions.

        Args:
            error: Exception from the Cloudflare SDK.

        Raises:
            CloudflareAuthError: For authentication failures.
            CloudflareRateLimitError: For rate limit errors.
            CloudflareNotFoundError: For missing resources.
            CloudflareValidationError: For invalid requests.
            CloudflareAPIError: For other API errors.
        """
        if isinstance(error, AuthenticationError):
            msg = "Authentication failed. Check your API token."
            raise CloudflareAuthError(msg, code=401) from error

        if isinstance(error, RateLimitError):
            msg = "Rate limit exceeded. Please wait before retrying."
            raise CloudflareRateLimitError(msg) from error

        if isinstance(error, NotFoundError):
            raise CloudflareNotFoundError(
                str(error),
                code=404,
            ) from error

        if isinstance(error, BadRequestError):
            raise CloudflareValidationError(
                str(error),
                code=400,
            ) from error

        if isinstance(error, APIConnectionError):
            msg = f"Connection error: {error}"
            raise CloudflareAPIError(msg) from error

        if isinstance(error, APIStatusError):
            raise CloudflareAPIError(
                str(error),
                code=getattr(error, "status_code", None),
            ) from error

        raise CloudflareAPIError(str(error)) from error

    # =========================================================================
    # IP List Operations
    # =========================================================================

    def list_ip_lists(self) -> list[IPList]:
        """List all IP lists in the account.

        Returns:
            List of IPList objects.

        Raises:
            CloudflareAPIError: If the API request fails.
        """
        try:
            response = self._client.rules.lists.list(account_id=self._account_id)
            lists = []
            for item in response:
                lists.append(
                    IPList(
                        id=item.id,
                        name=item.name,
                        description=item.description,
                        kind=ListKind(item.kind) if item.kind else ListKind.IP,
                        num_items=item.num_items or 0,
                        num_referencing_filters=item.num_referencing_filters or 0,
                        created_on=item.created_on,
                        modified_on=item.modified_on,
                    )
                )
            logger.debug("Listed %d IP lists", len(lists))
            return lists
        except Exception as e:
            self._handle_api_error(e)
            raise  # Unreachable but satisfies type checker

    def get_ip_list(self, list_id: str) -> IPList:
        """Get details of a specific IP list.

        Args:
            list_id: The list identifier.

        Returns:
            IPList object.

        Raises:
            CloudflareNotFoundError: If the list doesn't exist.
            CloudflareAPIError: If the API request fails.
        """
        try:
            item = self._client.rules.lists.get(
                list_id=list_id,
                account_id=self._account_id,
            )
            return IPList(
                id=item.id,
                name=item.name,
                description=item.description,
                kind=ListKind(item.kind) if item.kind else ListKind.IP,
                num_items=item.num_items or 0,
                num_referencing_filters=item.num_referencing_filters or 0,
                created_on=item.created_on,
                modified_on=item.modified_on,
            )
        except Exception as e:
            self._handle_api_error(e)
            raise

    def get_ip_list_by_name(self, name: str) -> IPList | None:
        """Get an IP list by name.

        Args:
            name: The list name to search for.

        Returns:
            IPList if found, None otherwise.

        Raises:
            CloudflareAPIError: If the API request fails.
        """
        lists = self.list_ip_lists()
        for ip_list in lists:
            if ip_list.name == name:
                return ip_list
        return None

    def create_ip_list(
        self,
        name: str,
        kind: str = "ip",
        description: str | None = None,
    ) -> IPList:
        """Create a new IP list.

        Args:
            name: List name (must be unique per account).
            kind: Type of list (ip, redirect, hostname, asn).
            description: Optional description.

        Returns:
            The created IPList.

        Raises:
            CloudflareConflictError: If a list with this name already exists.
            CloudflareValidationError: If the name or kind is invalid.
            CloudflareAPIError: If the API request fails.
        """
        try:
            response = self._client.rules.lists.create(
                account_id=self._account_id,
                kind=kind,
                name=name,
                description=description,
            )
            logger.info("Created IP list '%s' with ID %s", name, response.id)
            return IPList(
                id=response.id,
                name=response.name,
                description=response.description,
                kind=ListKind(response.kind) if response.kind else ListKind.IP,
                num_items=response.num_items or 0,
                num_referencing_filters=response.num_referencing_filters or 0,
                created_on=response.created_on,
                modified_on=response.modified_on,
            )
        except BadRequestError as e:
            if "already exists" in str(e).lower():
                msg = f"A list named '{name}' already exists"
                raise CloudflareConflictError(msg, code=409) from e
            self._handle_api_error(e)
            raise
        except Exception as e:
            self._handle_api_error(e)
            raise

    def update_ip_list(
        self,
        list_id: str,
        description: str | None = None,
    ) -> IPList:
        """Update an IP list's description.

        Args:
            list_id: The list identifier.
            description: New description.

        Returns:
            The updated IPList.

        Raises:
            CloudflareNotFoundError: If the list doesn't exist.
            CloudflareAPIError: If the API request fails.
        """
        try:
            response = self._client.rules.lists.update(
                list_id=list_id,
                account_id=self._account_id,
                description=description,
            )
            logger.info("Updated IP list %s", list_id)
            return IPList(
                id=response.id,
                name=response.name,
                description=response.description,
                kind=ListKind(response.kind) if response.kind else ListKind.IP,
                num_items=response.num_items or 0,
                num_referencing_filters=response.num_referencing_filters or 0,
                created_on=response.created_on,
                modified_on=response.modified_on,
            )
        except Exception as e:
            self._handle_api_error(e)
            raise

    def delete_ip_list(self, list_id: str) -> bool:
        """Delete an IP list and all its items.

        Args:
            list_id: The list identifier.

        Returns:
            True if deleted successfully.

        Raises:
            CloudflareNotFoundError: If the list doesn't exist.
            CloudflareConflictError: If the list is in use by firewall rules.
            CloudflareAPIError: If the API request fails.
        """
        try:
            self._client.rules.lists.delete(
                list_id=list_id,
                account_id=self._account_id,
            )
            logger.info("Deleted IP list %s", list_id)
            return True
        except BadRequestError as e:
            if "in use" in str(e).lower() or "referenced" in str(e).lower():
                msg = f"Cannot delete list {list_id}: it is referenced by firewall rules"
                raise CloudflareConflictError(msg, code=409) from e
            self._handle_api_error(e)
            raise
        except Exception as e:
            self._handle_api_error(e)
            raise

    # =========================================================================
    # IP List Item Operations
    # =========================================================================

    def get_ip_list_items(self, list_id: str) -> list[IPListItem]:
        """Get all items in an IP list.

        Args:
            list_id: The list identifier.

        Returns:
            List of IPListItem objects.

        Raises:
            CloudflareNotFoundError: If the list doesn't exist.
            CloudflareAPIError: If the API request fails.
        """
        try:
            response = self._client.rules.lists.items.list(
                list_id=list_id,
                account_id=self._account_id,
            )
            items = []
            for item in response:
                items.append(
                    IPListItem(
                        id=item.id,
                        ip=item.ip,
                        comment=item.comment,
                        created_on=item.created_on,
                        modified_on=item.modified_on,
                    )
                )
            logger.debug("Retrieved %d items from list %s", len(items), list_id)
            return items
        except Exception as e:
            self._handle_api_error(e)
            raise

    def add_ip_list_items(
        self,
        list_id: str,
        items: list[dict[str, Any] | IPListItemInput],
        wait_for_completion: bool = True,
    ) -> str | None:
        """Add items to an IP list.

        This is an asynchronous operation. By default, waits for completion.

        Args:
            list_id: The list identifier.
            items: List of items to add. Each item should have 'ip' and
                   optionally 'comment'.
            wait_for_completion: Whether to wait for the operation to complete.

        Returns:
            Operation ID if not waiting, None if completed.

        Raises:
            CloudflareNotFoundError: If the list doesn't exist.
            CloudflareBulkOperationError: If the operation fails.
            CloudflareConflictError: If another bulk operation is in progress.
            CloudflareAPIError: If the API request fails.
        """
        try:
            # Convert to API format
            api_items = []
            for item in items:
                if isinstance(item, IPListItemInput):
                    api_items.append(item.to_api_dict())
                else:
                    api_items.append(item)

            response = self._client.rules.lists.items.create(
                list_id=list_id,
                account_id=self._account_id,
                body=api_items,
            )

            operation_id = response.operation_id
            logger.info(
                "Started add operation %s for %d items to list %s",
                operation_id,
                len(items),
                list_id,
            )

            if wait_for_completion and operation_id:
                self._wait_for_bulk_operation(operation_id)
                return None

            return operation_id
        except BadRequestError as e:
            if "pending" in str(e).lower():
                msg = "Another bulk operation is already in progress"
                raise CloudflareConflictError(msg, code=409) from e
            self._handle_api_error(e)
            raise
        except Exception as e:
            self._handle_api_error(e)
            raise

    def replace_ip_list_items(
        self,
        list_id: str,
        items: list[dict[str, Any] | IPListItemInput],
        wait_for_completion: bool = True,
    ) -> str | None:
        """Replace all items in an IP list.

        Removes all existing items and adds the provided items.
        This is an asynchronous operation.

        Args:
            list_id: The list identifier.
            items: List of items to set. Each item should have 'ip' and
                   optionally 'comment'.
            wait_for_completion: Whether to wait for the operation to complete.

        Returns:
            Operation ID if not waiting, None if completed.

        Raises:
            CloudflareNotFoundError: If the list doesn't exist.
            CloudflareBulkOperationError: If the operation fails.
            CloudflareConflictError: If another bulk operation is in progress.
            CloudflareAPIError: If the API request fails.
        """
        try:
            # Convert to API format
            api_items = []
            for item in items:
                if isinstance(item, IPListItemInput):
                    api_items.append(item.to_api_dict())
                else:
                    api_items.append(item)

            response = self._client.rules.lists.items.update(
                list_id=list_id,
                account_id=self._account_id,
                body=api_items,
            )

            operation_id = response.operation_id
            logger.info(
                "Started replace operation %s with %d items for list %s",
                operation_id,
                len(items),
                list_id,
            )

            if wait_for_completion and operation_id:
                self._wait_for_bulk_operation(operation_id)
                return None

            return operation_id
        except BadRequestError as e:
            if "pending" in str(e).lower():
                msg = "Another bulk operation is already in progress"
                raise CloudflareConflictError(msg, code=409) from e
            self._handle_api_error(e)
            raise
        except Exception as e:
            self._handle_api_error(e)
            raise

    def delete_ip_list_items(
        self,
        list_id: str,
        item_ids: list[str],
        wait_for_completion: bool = True,
    ) -> str | None:
        """Delete specific items from an IP list.

        Args:
            list_id: The list identifier.
            item_ids: List of item IDs to delete.
            wait_for_completion: Whether to wait for the operation to complete.

        Returns:
            Operation ID if not waiting, None if completed.

        Raises:
            CloudflareNotFoundError: If the list doesn't exist.
            CloudflareBulkOperationError: If the operation fails.
            CloudflareAPIError: If the API request fails.
        """
        try:
            # Format items for deletion
            items_to_delete = [{"id": item_id} for item_id in item_ids]

            response = self._client.rules.lists.items.delete(
                list_id=list_id,
                account_id=self._account_id,
                items=items_to_delete,
            )

            operation_id = response.operation_id
            logger.info(
                "Started delete operation %s for %d items from list %s",
                operation_id,
                len(item_ids),
                list_id,
            )

            if wait_for_completion and operation_id:
                self._wait_for_bulk_operation(operation_id)
                return None

            return operation_id
        except Exception as e:
            self._handle_api_error(e)
            raise

    # =========================================================================
    # Bulk Operation Helpers
    # =========================================================================

    def get_bulk_operation_status(self, operation_id: str) -> BulkOperation:
        """Get the status of a bulk operation.

        Args:
            operation_id: The operation identifier.

        Returns:
            BulkOperation with current status.

        Raises:
            CloudflareNotFoundError: If the operation doesn't exist.
            CloudflareAPIError: If the API request fails.
        """
        try:
            response = self._client.rules.lists.bulk_operations.get(
                operation_id=operation_id,
                account_id=self._account_id,
            )
            return BulkOperation(
                id=response.id,
                status=BulkOperationStatus(response.status),
                error=response.error,
                completed=response.completed,
            )
        except Exception as e:
            self._handle_api_error(e)
            raise

    def _wait_for_bulk_operation(self, operation_id: str) -> BulkOperation:
        """Wait for a bulk operation to complete.

        Args:
            operation_id: The operation identifier.

        Returns:
            The final BulkOperation status.

        Raises:
            CloudflareBulkOperationError: If the operation fails or times out.
        """
        start_time = time.time()
        timeout = self.settings.bulk_operation_timeout
        poll_interval = self.settings.bulk_operation_poll_interval

        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                msg = f"Bulk operation {operation_id} timed out after {timeout}s"
                raise CloudflareBulkOperationError(
                    msg, operation_id=operation_id, status="timeout"
                )

            status = self.get_bulk_operation_status(operation_id)

            if status.status == BulkOperationStatus.COMPLETED:
                logger.debug("Bulk operation %s completed", operation_id)
                return status

            if status.status == BulkOperationStatus.FAILED:
                msg = f"Bulk operation {operation_id} failed: {status.error}"
                raise CloudflareBulkOperationError(
                    msg, operation_id=operation_id, status="failed"
                )

            logger.debug(
                "Bulk operation %s status: %s (%.1fs elapsed)",
                operation_id,
                status.status.value,
                elapsed,
            )
            time.sleep(poll_interval)

    # =========================================================================
    # Convenience Methods
    # =========================================================================

    def ensure_ip_list(
        self,
        name: str,
        kind: str = "ip",
        description: str | None = None,
    ) -> IPList:
        """Get or create an IP list by name.

        Args:
            name: List name.
            kind: Type of list if creating.
            description: Description if creating.

        Returns:
            The existing or newly created IPList.

        Raises:
            CloudflareAPIError: If the API request fails.
        """
        existing = self.get_ip_list_by_name(name)
        if existing:
            logger.debug("Found existing IP list '%s' (%s)", name, existing.id)
            return existing

        return self.create_ip_list(name=name, kind=kind, description=description)

    def sync_ip_list(
        self,
        list_id: str,
        ips: list[str],
        comments: dict[str, str] | None = None,
    ) -> None:
        """Sync an IP list to contain exactly the specified IPs.

        Args:
            list_id: The list identifier.
            ips: List of IP addresses/CIDRs that should be in the list.
            comments: Optional mapping of IP to comment.

        Raises:
            CloudflareAPIError: If the API request fails.
        """
        comments = comments or {}
        items = [
            {"ip": ip, "comment": comments.get(ip)}
            for ip in ips
        ]
        self.replace_ip_list_items(list_id, items)
        logger.info("Synced list %s with %d IPs", list_id, len(ips))
