"""Pytest configuration for cloudflare-auth tests."""

from datetime import datetime, timezone

import pytest

from cloudflare_auth.settings import reset_settings

# Test constants
TEST_ISSUER = "https://test.cloudflareaccess.com"
TEST_EMAIL = "test@example.com"
TEST_USER_ID = "test-user-id"
TEST_AUDIENCE = "test-audience"


@pytest.fixture
def sample_jwt_payload():
    """Sample JWT payload for testing."""
    return {
        "iss": TEST_ISSUER,
        "sub": TEST_USER_ID,
        "aud": [TEST_AUDIENCE],
        "email": TEST_EMAIL,
        "iat": 1700000000,
        "exp": 1700003600,
    }


@pytest.fixture
def valid_jwt_payload():
    """JWT payload with future expiration."""
    now = int(datetime.now(tz=timezone.utc).timestamp())
    return {
        "iss": TEST_ISSUER,
        "sub": TEST_USER_ID,
        "aud": [TEST_AUDIENCE],
        "email": TEST_EMAIL,
        "iat": now,
        "exp": now + 3600,
    }


@pytest.fixture
def expired_jwt_payload():
    """JWT payload with past expiration."""
    now = int(datetime.now(tz=timezone.utc).timestamp())
    return {
        "iss": TEST_ISSUER,
        "sub": TEST_USER_ID,
        "aud": [TEST_AUDIENCE],
        "email": TEST_EMAIL,
        "iat": now - 7200,
        "exp": now - 3600,
    }


@pytest.fixture(autouse=True)
def reset_settings_after_test():
    """Reset settings singleton after each test."""
    yield
    reset_settings()
