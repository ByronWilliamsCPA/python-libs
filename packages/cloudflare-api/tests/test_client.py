"""Tests for cloudflare_api client."""

from unittest.mock import MagicMock, patch

import pytest
from cloudflare._exceptions import AuthenticationError, BadRequestError, NotFoundError

from cloudflare_api.client import CloudflareAPIClient
from cloudflare_api.exceptions import (
    CloudflareAuthError,
    CloudflareBulkOperationError,
    CloudflareConflictError,
    CloudflareNotFoundError,
    CloudflareValidationError,
)
from cloudflare_api.models import BulkOperationStatus, ListKind
from cloudflare_api.settings import CloudflareAPISettings


class TestCloudflareAPIClientInit:
    """Test suite for CloudflareAPIClient initialization."""

    def test_init_with_settings(self, mock_env_vars, mock_cloudflare_client):
        """Test client initialization with explicit settings."""
        settings = CloudflareAPISettings()
        client = CloudflareAPIClient(settings=settings)

        assert client.settings == settings
        assert client._account_id == "test-account-id-12345"

    def test_init_from_environment(self, mock_env_vars, mock_cloudflare_client):
        """Test client initialization from environment variables."""
        client = CloudflareAPIClient()

        assert client._account_id == "test-account-id-12345"


class TestIPListOperations:
    """Test suite for IP list operations."""

    @pytest.fixture
    def client(self, mock_env_vars, mock_cloudflare_client):
        """Create a client with mocked Cloudflare SDK."""
        return CloudflareAPIClient()

    def test_list_ip_lists(
        self, client, mock_cloudflare_client, sample_ip_list_response
    ):
        """Test listing IP lists."""
        mock_cloudflare_client.rules.lists.list.return_value = [sample_ip_list_response]

        lists = client.list_ip_lists()

        assert len(lists) == 1
        assert lists[0].id == "test-list-id-67890"
        assert lists[0].name == "test-list"
        assert lists[0].kind == ListKind.IP

    def test_list_ip_lists_empty(self, client, mock_cloudflare_client):
        """Test listing IP lists when none exist."""
        mock_cloudflare_client.rules.lists.list.return_value = []

        lists = client.list_ip_lists()

        assert lists == []

    def test_get_ip_list(self, client, mock_cloudflare_client, sample_ip_list_response):
        """Test getting a specific IP list."""
        mock_cloudflare_client.rules.lists.get.return_value = sample_ip_list_response

        ip_list = client.get_ip_list("test-list-id-67890")

        assert ip_list.id == "test-list-id-67890"
        assert ip_list.name == "test-list"

    def test_get_ip_list_not_found(self, client, mock_cloudflare_client):
        """Test getting a non-existent IP list."""
        mock_cloudflare_client.rules.lists.get.side_effect = NotFoundError(
            "Not found", response=MagicMock(), body=None
        )

        with pytest.raises(CloudflareNotFoundError):
            client.get_ip_list("nonexistent")

    def test_get_ip_list_by_name_found(
        self, client, mock_cloudflare_client, sample_ip_list_response
    ):
        """Test getting IP list by name when it exists."""
        mock_cloudflare_client.rules.lists.list.return_value = [sample_ip_list_response]

        ip_list = client.get_ip_list_by_name("test-list")

        assert ip_list is not None
        assert ip_list.name == "test-list"

    def test_get_ip_list_by_name_not_found(self, client, mock_cloudflare_client):
        """Test getting IP list by name when it doesn't exist."""
        mock_cloudflare_client.rules.lists.list.return_value = []

        ip_list = client.get_ip_list_by_name("nonexistent")

        assert ip_list is None

    def test_create_ip_list(
        self, client, mock_cloudflare_client, sample_ip_list_response
    ):
        """Test creating a new IP list."""
        mock_cloudflare_client.rules.lists.create.return_value = sample_ip_list_response

        ip_list = client.create_ip_list(
            name="new-list",
            kind="ip",
            description="New list",
        )

        assert ip_list.id == "test-list-id-67890"
        mock_cloudflare_client.rules.lists.create.assert_called_once()

    def test_create_ip_list_already_exists(self, client, mock_cloudflare_client):
        """Test creating a list that already exists."""
        mock_cloudflare_client.rules.lists.create.side_effect = BadRequestError(
            "List already exists", response=MagicMock(), body=None
        )

        with pytest.raises(CloudflareConflictError):
            client.create_ip_list(name="existing-list")

    def test_delete_ip_list(self, client, mock_cloudflare_client):
        """Test deleting an IP list."""
        mock_cloudflare_client.rules.lists.delete.return_value = None

        result = client.delete_ip_list("test-list-id")

        assert result is True
        mock_cloudflare_client.rules.lists.delete.assert_called_once()

    def test_delete_ip_list_in_use(self, client, mock_cloudflare_client):
        """Test deleting a list that's in use."""
        mock_cloudflare_client.rules.lists.delete.side_effect = BadRequestError(
            "List is in use by firewall rules", response=MagicMock(), body=None
        )

        with pytest.raises(CloudflareConflictError):
            client.delete_ip_list("in-use-list")


class TestIPListItemOperations:
    """Test suite for IP list item operations."""

    @pytest.fixture
    def client(self, mock_env_vars, mock_cloudflare_client):
        """Create a client with mocked Cloudflare SDK."""
        return CloudflareAPIClient()

    def test_get_ip_list_items(
        self, client, mock_cloudflare_client, sample_ip_list_item_response
    ):
        """Test getting items from an IP list."""
        mock_cloudflare_client.rules.lists.items.list.return_value = [
            sample_ip_list_item_response
        ]

        items = client.get_ip_list_items("test-list-id")

        assert len(items) == 1
        assert items[0].ip == "192.168.1.1"
        assert items[0].comment == "Test IP"

    def test_add_ip_list_items(
        self,
        client,
        mock_cloudflare_client,
        sample_bulk_operation_response,
        sample_bulk_operation_status,
    ):
        """Test adding items to an IP list."""
        mock_cloudflare_client.rules.lists.items.create.return_value = (
            sample_bulk_operation_response
        )
        mock_cloudflare_client.rules.lists.bulk_operations.get.return_value = (
            sample_bulk_operation_status
        )

        result = client.add_ip_list_items(
            list_id="test-list-id",
            items=[{"ip": "1.2.3.4", "comment": "New IP"}],
        )

        assert result is None  # Waited for completion
        mock_cloudflare_client.rules.lists.items.create.assert_called_once()

    def test_add_ip_list_items_no_wait(
        self, client, mock_cloudflare_client, sample_bulk_operation_response
    ):
        """Test adding items without waiting for completion."""
        mock_cloudflare_client.rules.lists.items.create.return_value = (
            sample_bulk_operation_response
        )

        result = client.add_ip_list_items(
            list_id="test-list-id",
            items=[{"ip": "1.2.3.4"}],
            wait_for_completion=False,
        )

        assert result == "test-operation-id-abcde"

    def test_replace_ip_list_items(
        self,
        client,
        mock_cloudflare_client,
        sample_bulk_operation_response,
        sample_bulk_operation_status,
    ):
        """Test replacing all items in a list."""
        mock_cloudflare_client.rules.lists.items.update.return_value = (
            sample_bulk_operation_response
        )
        mock_cloudflare_client.rules.lists.bulk_operations.get.return_value = (
            sample_bulk_operation_status
        )

        result = client.replace_ip_list_items(
            list_id="test-list-id",
            items=[{"ip": "5.6.7.8"}],
        )

        assert result is None
        mock_cloudflare_client.rules.lists.items.update.assert_called_once()

    def test_delete_ip_list_items(
        self,
        client,
        mock_cloudflare_client,
        sample_bulk_operation_response,
        sample_bulk_operation_status,
    ):
        """Test deleting specific items."""
        mock_cloudflare_client.rules.lists.items.delete.return_value = (
            sample_bulk_operation_response
        )
        mock_cloudflare_client.rules.lists.bulk_operations.get.return_value = (
            sample_bulk_operation_status
        )

        result = client.delete_ip_list_items(
            list_id="test-list-id",
            item_ids=["item-1", "item-2"],
        )

        assert result is None
        mock_cloudflare_client.rules.lists.items.delete.assert_called_once()


class TestBulkOperations:
    """Test suite for bulk operation handling."""

    @pytest.fixture
    def client(self, mock_env_vars, mock_cloudflare_client):
        """Create a client with mocked Cloudflare SDK."""
        return CloudflareAPIClient()

    def test_get_bulk_operation_status(
        self, client, mock_cloudflare_client, sample_bulk_operation_status
    ):
        """Test getting bulk operation status."""
        mock_cloudflare_client.rules.lists.bulk_operations.get.return_value = (
            sample_bulk_operation_status
        )

        status = client.get_bulk_operation_status("test-op-id")

        assert status.id == "test-operation-id-abcde"
        assert status.status == BulkOperationStatus.COMPLETED

    def test_wait_for_bulk_operation_completed(
        self, client, mock_cloudflare_client, sample_bulk_operation_status
    ):
        """Test waiting for a bulk operation that completes."""
        mock_cloudflare_client.rules.lists.bulk_operations.get.return_value = (
            sample_bulk_operation_status
        )

        result = client._wait_for_bulk_operation("test-op-id")

        assert result.status == BulkOperationStatus.COMPLETED

    def test_wait_for_bulk_operation_failed(self, client, mock_cloudflare_client):
        """Test waiting for a bulk operation that fails."""
        mock_status = MagicMock()
        mock_status.id = "test-op-id"
        mock_status.status = "failed"
        mock_status.error = "Invalid IP format"
        mock_status.completed = None

        mock_cloudflare_client.rules.lists.bulk_operations.get.return_value = mock_status

        with pytest.raises(CloudflareBulkOperationError) as exc_info:
            client._wait_for_bulk_operation("test-op-id")

        assert "failed" in str(exc_info.value)


class TestConvenienceMethods:
    """Test suite for convenience methods."""

    @pytest.fixture
    def client(self, mock_env_vars, mock_cloudflare_client):
        """Create a client with mocked Cloudflare SDK."""
        return CloudflareAPIClient()

    def test_ensure_ip_list_exists(
        self, client, mock_cloudflare_client, sample_ip_list_response
    ):
        """Test ensure_ip_list when list already exists."""
        mock_cloudflare_client.rules.lists.list.return_value = [sample_ip_list_response]

        ip_list = client.ensure_ip_list("test-list")

        assert ip_list.id == "test-list-id-67890"
        # Should not call create
        mock_cloudflare_client.rules.lists.create.assert_not_called()

    def test_ensure_ip_list_creates(
        self, client, mock_cloudflare_client, sample_ip_list_response
    ):
        """Test ensure_ip_list creates new list when not found."""
        mock_cloudflare_client.rules.lists.list.return_value = []
        mock_cloudflare_client.rules.lists.create.return_value = sample_ip_list_response

        ip_list = client.ensure_ip_list("new-list", description="Test")

        assert ip_list.id == "test-list-id-67890"
        mock_cloudflare_client.rules.lists.create.assert_called_once()

    def test_sync_ip_list(
        self,
        client,
        mock_cloudflare_client,
        sample_bulk_operation_response,
        sample_bulk_operation_status,
    ):
        """Test syncing IP list to specific IPs."""
        mock_cloudflare_client.rules.lists.items.update.return_value = (
            sample_bulk_operation_response
        )
        mock_cloudflare_client.rules.lists.bulk_operations.get.return_value = (
            sample_bulk_operation_status
        )

        client.sync_ip_list(
            list_id="test-list-id",
            ips=["1.2.3.4", "5.6.7.8"],
            comments={"1.2.3.4": "First IP"},
        )

        mock_cloudflare_client.rules.lists.items.update.assert_called_once()


class TestErrorHandling:
    """Test suite for error handling."""

    @pytest.fixture
    def client(self, mock_env_vars, mock_cloudflare_client):
        """Create a client with mocked Cloudflare SDK."""
        return CloudflareAPIClient()

    def test_authentication_error(self, client, mock_cloudflare_client):
        """Test handling of authentication errors."""
        mock_cloudflare_client.rules.lists.list.side_effect = AuthenticationError(
            "Invalid token", response=MagicMock(), body=None
        )

        with pytest.raises(CloudflareAuthError):
            client.list_ip_lists()

    def test_validation_error(self, client, mock_cloudflare_client):
        """Test handling of validation errors."""
        mock_cloudflare_client.rules.lists.create.side_effect = BadRequestError(
            "Invalid name format", response=MagicMock(), body=None
        )

        with pytest.raises(CloudflareValidationError):
            client.create_ip_list(name="invalid@name")

    def test_not_found_error(self, client, mock_cloudflare_client):
        """Test handling of not found errors."""
        mock_cloudflare_client.rules.lists.get.side_effect = NotFoundError(
            "List not found", response=MagicMock(), body=None
        )

        with pytest.raises(CloudflareNotFoundError):
            client.get_ip_list("nonexistent")
