"""Pytest configuration for gcs-utilities tests."""

import pytest


@pytest.fixture
def mock_bucket_name() -> str:
    """Sample bucket name for testing."""
    return "test-bucket"


@pytest.fixture
def mock_blob_name() -> str:
    """Sample blob name for testing."""
    return "test/path/file.txt"
