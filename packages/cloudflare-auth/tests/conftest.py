"""Pytest configuration for cloudflare-auth tests."""

import pytest


@pytest.fixture
def sample_jwt_payload():
    """Sample JWT payload for testing."""
    return {
        "iss": "https://test.cloudflareaccess.com",
        "sub": "test-user-id",
        "aud": ["test-audience"],
        "email": "test@example.com",
        "iat": 1700000000,
        "exp": 1700003600,
    }
