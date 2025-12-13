"""Tests for cloudflare_auth models."""

from datetime import datetime

import pytest

from cloudflare_auth.models import CloudflareJWTClaims, CloudflareUser
from cloudflare_auth.whitelist import UserTier


class TestCloudflareJWTClaims:
    """Test suite for CloudflareJWTClaims model."""

    def test_create_claims_with_required_fields(self, sample_jwt_payload):
        """Test creating claims with required fields."""
        claims = CloudflareJWTClaims(**sample_jwt_payload)

        assert claims.email == "test@example.com"
        assert claims.iss == "https://test.cloudflareaccess.com"
        assert claims.aud == ["test-audience"]
        assert claims.sub == "test-user-id"
        assert claims.iat == 1700000000
        assert claims.exp == 1700003600

    def test_claims_with_optional_fields(self, sample_jwt_payload):
        """Test claims with optional fields."""
        sample_jwt_payload["nonce"] = "test-nonce"
        sample_jwt_payload["identity_nonce"] = "test-identity-nonce"
        sample_jwt_payload["custom"] = {"role": "admin"}

        claims = CloudflareJWTClaims(**sample_jwt_payload)

        assert claims.nonce == "test-nonce"
        assert claims.identity_nonce == "test-identity-nonce"
        assert claims.custom == {"role": "admin"}

    def test_issued_at_property(self, sample_jwt_payload):
        """Test issued_at datetime property."""
        claims = CloudflareJWTClaims(**sample_jwt_payload)
        issued_at = claims.issued_at

        assert isinstance(issued_at, datetime)
        assert issued_at.timestamp() == sample_jwt_payload["iat"]

    def test_expires_at_property(self, sample_jwt_payload):
        """Test expires_at datetime property."""
        claims = CloudflareJWTClaims(**sample_jwt_payload)
        expires_at = claims.expires_at

        assert isinstance(expires_at, datetime)
        assert expires_at.timestamp() == sample_jwt_payload["exp"]

    def test_is_expired_false_for_future_expiration(self, sample_jwt_payload):
        """Test is_expired returns False for future expiration."""
        # Set expiration to far in the future
        sample_jwt_payload["exp"] = int(datetime.now().timestamp()) + 3600
        claims = CloudflareJWTClaims(**sample_jwt_payload)

        assert claims.is_expired is False

    def test_is_expired_true_for_past_expiration(self, sample_jwt_payload):
        """Test is_expired returns True for past expiration."""
        # Set expiration to the past
        sample_jwt_payload["exp"] = int(datetime.now().timestamp()) - 3600
        claims = CloudflareJWTClaims(**sample_jwt_payload)

        assert claims.is_expired is True

    def test_get_audience_list_from_string(self, sample_jwt_payload):
        """Test get_audience_list when aud is a string."""
        sample_jwt_payload["aud"] = "single-audience"
        claims = CloudflareJWTClaims(**sample_jwt_payload)

        assert claims.get_audience_list() == ["single-audience"]

    def test_get_audience_list_from_list(self, sample_jwt_payload):
        """Test get_audience_list when aud is already a list."""
        claims = CloudflareJWTClaims(**sample_jwt_payload)

        assert claims.get_audience_list() == ["test-audience"]


class TestCloudflareUser:
    """Test suite for CloudflareUser model."""

    @pytest.fixture
    def sample_claims(self, sample_jwt_payload):
        """Create sample claims for user tests."""
        return CloudflareJWTClaims(**sample_jwt_payload)

    def test_create_user_from_claims(self, sample_claims):
        """Test creating user from JWT claims."""
        user = CloudflareUser.from_jwt_claims(sample_claims)

        assert user.email == "test@example.com"
        assert user.user_id == "test-user-id"
        assert user.claims == sample_claims
        assert user.user_tier == UserTier.LIMITED
        assert user.is_admin is False
        assert user.session_id is None

    def test_create_user_with_admin_tier(self, sample_claims):
        """Test creating user with admin tier."""
        user = CloudflareUser.from_jwt_claims(
            sample_claims,
            user_tier=UserTier.ADMIN,
            is_admin=True,
        )

        assert user.user_tier == UserTier.ADMIN
        assert user.is_admin is True

    def test_create_user_with_session_id(self, sample_claims):
        """Test creating user with session ID."""
        user = CloudflareUser.from_jwt_claims(
            sample_claims,
            session_id="test-session-123",
        )

        assert user.session_id == "test-session-123"

    def test_email_domain_property(self, sample_claims):
        """Test email_domain property."""
        user = CloudflareUser.from_jwt_claims(sample_claims)

        assert user.email_domain == "example.com"

    def test_email_username_property(self, sample_claims):
        """Test email_username property."""
        user = CloudflareUser.from_jwt_claims(sample_claims)

        assert user.email_username == "test"

    def test_has_email_domain_true(self, sample_claims):
        """Test has_email_domain returns True for matching domain."""
        user = CloudflareUser.from_jwt_claims(sample_claims)

        assert user.has_email_domain("example.com") is True
        assert user.has_email_domain("EXAMPLE.COM") is True  # Case insensitive

    def test_has_email_domain_false(self, sample_claims):
        """Test has_email_domain returns False for non-matching domain."""
        user = CloudflareUser.from_jwt_claims(sample_claims)

        assert user.has_email_domain("other.com") is False

    def test_can_access_premium_models_admin(self, sample_claims):
        """Test premium access for admin tier."""
        user = CloudflareUser.from_jwt_claims(
            sample_claims,
            user_tier=UserTier.ADMIN,
        )

        assert user.can_access_premium_models is True

    def test_can_access_premium_models_full(self, sample_claims):
        """Test premium access for full tier."""
        user = CloudflareUser.from_jwt_claims(
            sample_claims,
            user_tier=UserTier.FULL,
        )

        assert user.can_access_premium_models is True

    def test_can_access_premium_models_limited(self, sample_claims):
        """Test premium access for limited tier."""
        user = CloudflareUser.from_jwt_claims(
            sample_claims,
            user_tier=UserTier.LIMITED,
        )

        assert user.can_access_premium_models is False

    def test_role_property_admin(self, sample_claims):
        """Test role property for admin user."""
        user = CloudflareUser.from_jwt_claims(
            sample_claims,
            is_admin=True,
        )

        assert user.role == "admin"

    def test_role_property_user(self, sample_claims):
        """Test role property for regular user."""
        user = CloudflareUser.from_jwt_claims(sample_claims)

        assert user.role == "user"

    def test_model_dump_safe(self, sample_claims):
        """Test model_dump_safe returns expected fields."""
        user = CloudflareUser.from_jwt_claims(
            sample_claims,
            user_tier=UserTier.FULL,
            is_admin=False,
        )

        safe_dict = user.model_dump_safe()

        assert "email" in safe_dict
        assert "user_id" in safe_dict
        assert "email_domain" in safe_dict
        assert "authenticated_at" in safe_dict
        assert "user_tier" in safe_dict
        assert "is_admin" in safe_dict
        assert "can_access_premium" in safe_dict
        assert "role" in safe_dict
        # Ensure claims are not included (security)
        assert "claims" not in safe_dict
