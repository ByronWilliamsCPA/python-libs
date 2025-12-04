"""Pytest configuration for gcs-utilities tests."""

import pytest


@pytest.fixture
def mock_bucket_name():
    """Sample bucket name for testing."""
    return "test-bucket"


@pytest.fixture
def mock_blob_name():
    """Sample blob name for testing."""
    return "test/path/file.txt"
