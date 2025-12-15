"""Pytest configuration for cloudflare-api tests."""

import os
from unittest.mock import MagicMock, patch

import pytest
from cloudflare_api.settings import reset_settings

# Test constants
TEST_ACCOUNT_ID = "test-account-id-12345"
TEST_API_TOKEN = "test-api-token-secret"
TEST_LIST_ID = "test-list-id-67890"
TEST_OPERATION_ID = "test-operation-id-abcde"


@pytest.fixture(autouse=True)
def reset_settings_after_test():
    """Reset settings singleton after each test."""
    yield
    reset_settings()


@pytest.fixture
def mock_env_vars():
    """Set required environment variables for testing."""
    with patch.dict(
        os.environ,
        {
            "CLOUDFLARE_API_TOKEN": TEST_API_TOKEN,
            "CLOUDFLARE_ACCOUNT_ID": TEST_ACCOUNT_ID,
        },
    ):
        yield


@pytest.fixture
def mock_cloudflare_client():
    """Create a mock Cloudflare client."""
    with patch("cloudflare_api.client.Cloudflare") as mock_cf:
        mock_instance = MagicMock()
        mock_cf.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def sample_ip_list_response():
    """Sample IP list response from Cloudflare API."""
    mock_list = MagicMock()
    mock_list.id = TEST_LIST_ID
    mock_list.name = "test-list"
    mock_list.description = "Test IP list"
    mock_list.kind = "ip"
    mock_list.num_items = 5
    mock_list.num_referencing_filters = 0
    mock_list.created_on = None
    mock_list.modified_on = None
    return mock_list


@pytest.fixture
def sample_ip_list_item_response():
    """Sample IP list item response."""
    mock_item = MagicMock()
    mock_item.id = "item-id-123"
    mock_item.ip = "192.168.1.1"
    mock_item.comment = "Test IP"
    mock_item.created_on = None
    mock_item.modified_on = None
    return mock_item


@pytest.fixture
def sample_bulk_operation_response():
    """Sample bulk operation response."""
    mock_op = MagicMock()
    mock_op.operation_id = TEST_OPERATION_ID
    return mock_op


@pytest.fixture
def sample_bulk_operation_status():
    """Sample bulk operation status response."""
    mock_status = MagicMock()
    mock_status.id = TEST_OPERATION_ID
    mock_status.status = "completed"
    mock_status.error = None
    mock_status.completed = None
    return mock_status
