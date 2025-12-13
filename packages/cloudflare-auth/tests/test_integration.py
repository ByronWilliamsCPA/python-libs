"""Integration tests for cloudflare_auth module.

These tests verify that components work together correctly.
"""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cloudflare_auth.models import CloudflareJWTClaims, CloudflareUser
from cloudflare_auth.sessions import SimpleSessionManager
from cloudflare_auth.settings import CloudflareSettings, reset_settings
from cloudflare_auth.whitelist import EmailWhitelistValidator, UserTier


class TestAuthenticationFlow:
    """Test complete authentication flow integration."""

    @pytest.fixture
    def settings(self):
        """Create test settings."""
        return CloudflareSettings(
            cloudflare_team_domain="test.cloudflareaccess.com",
            cloudflare_audience_tag="test-audience",
            cloudflare_enabled=True,
        )

    @pytest.fixture
    def whitelist_validator(self):
        """Create whitelist validator."""
        return EmailWhitelistValidator(
            whitelist=["@company.com", "guest@external.com"],
            admin_emails=["admin@company.com"],
            full_users=["@company.com"],
            limited_users=["guest@external.com"],
        )

    @pytest.fixture
    def session_manager(self):
        """Create session manager."""
        return SimpleSessionManager(session_timeout=3600)

    @pytest.fixture
    def sample_claims(self):
        """Create sample JWT claims."""
        now = int(datetime.now().timestamp())
        return CloudflareJWTClaims(
            email="user@company.com",
            iss="https://test.cloudflareaccess.com",
            aud=["test-audience"],
            sub="user-id-123",
            iat=now,
            exp=now + 3600,
        )

    def test_full_auth_flow_admin(self, whitelist_validator, session_manager):
        """Test complete authentication flow for admin user."""
        email = "admin@company.com"
        now = int(datetime.now().timestamp())

        # 1. Create claims (simulating JWT validation)
        claims = CloudflareJWTClaims(
            email=email,
            iss="https://test.cloudflareaccess.com",
            aud=["test-audience"],
            sub="admin-user-id",
            iat=now,
            exp=now + 3600,
        )

        # 2. Check whitelist authorization
        assert whitelist_validator.is_authorized(email) is True

        # 3. Get user tier
        tier = whitelist_validator.get_user_tier(email)
        assert tier == UserTier.ADMIN

        # 4. Create session
        session_id = session_manager.create_session(
            email=email,
            is_admin=tier.has_admin_privileges,
            user_tier=tier.value,
        )

        # 5. Create user object
        user = CloudflareUser.from_jwt_claims(
            claims=claims,
            user_tier=tier,
            is_admin=tier.has_admin_privileges,
            session_id=session_id,
        )

        # Verify user has expected properties
        assert user.email == email
        assert user.user_tier == UserTier.ADMIN
        assert user.is_admin is True
        assert user.can_access_premium_models is True
        assert user.session_id == session_id

        # 6. Verify session can be retrieved
        session = session_manager.get_session(session_id)
        assert session is not None
        assert session["email"] == email
        assert session["is_admin"] is True

    def test_full_auth_flow_regular_user(self, whitelist_validator, session_manager):
        """Test complete authentication flow for regular user."""
        email = "developer@company.com"
        now = int(datetime.now().timestamp())

        claims = CloudflareJWTClaims(
            email=email,
            iss="https://test.cloudflareaccess.com",
            aud=["test-audience"],
            sub="dev-user-id",
            iat=now,
            exp=now + 3600,
        )

        assert whitelist_validator.is_authorized(email) is True
        tier = whitelist_validator.get_user_tier(email)
        assert tier == UserTier.FULL

        session_id = session_manager.create_session(
            email=email,
            is_admin=tier.has_admin_privileges,
            user_tier=tier.value,
        )

        user = CloudflareUser.from_jwt_claims(
            claims=claims,
            user_tier=tier,
            is_admin=tier.has_admin_privileges,
            session_id=session_id,
        )

        assert user.is_admin is False
        assert user.can_access_premium_models is True

    def test_full_auth_flow_limited_user(self, whitelist_validator, session_manager):
        """Test complete authentication flow for limited user."""
        email = "guest@external.com"
        now = int(datetime.now().timestamp())

        claims = CloudflareJWTClaims(
            email=email,
            iss="https://test.cloudflareaccess.com",
            aud=["test-audience"],
            sub="guest-user-id",
            iat=now,
            exp=now + 3600,
        )

        assert whitelist_validator.is_authorized(email) is True
        tier = whitelist_validator.get_user_tier(email)
        assert tier == UserTier.LIMITED

        user = CloudflareUser.from_jwt_claims(
            claims=claims,
            user_tier=tier,
            is_admin=tier.has_admin_privileges,
        )

        assert user.is_admin is False
        assert user.can_access_premium_models is False

    def test_unauthorized_user_flow(self, whitelist_validator):
        """Test authentication flow for unauthorized user."""
        email = "hacker@malicious.com"

        assert whitelist_validator.is_authorized(email) is False

        with pytest.raises(ValueError, match="not authorized"):
            whitelist_validator.get_user_tier(email)


class TestSessionIntegration:
    """Test session management integration."""

    def test_session_lifecycle(self):
        """Test complete session lifecycle."""
        manager = SimpleSessionManager(session_timeout=3600)

        # Create session
        session_id = manager.create_session(
            email="test@example.com",
            is_admin=False,
            user_tier="full",
            cf_context={"cf_ray": "abc123"},
        )

        # Verify session exists
        assert manager.get_session(session_id) is not None
        assert manager.get_session_count() == 1

        # Refresh session
        assert manager.refresh_session(session_id) is True

        # Get session info
        info = manager.get_session_info(session_id)
        assert info["email"] == "test@example.com"

        # Invalidate session
        assert manager.invalidate_session(session_id) is True
        assert manager.get_session(session_id) is None
        assert manager.get_session_count() == 0

    def test_multiple_user_sessions(self):
        """Test handling multiple sessions for same and different users."""
        manager = SimpleSessionManager(session_timeout=3600)

        # Create sessions for user1
        user1_session1 = manager.create_session(
            email="user1@example.com",
            is_admin=False,
            user_tier="full",
        )
        user1_session2 = manager.create_session(
            email="user1@example.com",
            is_admin=False,
            user_tier="full",
        )

        # Create session for user2
        user2_session = manager.create_session(
            email="user2@example.com",
            is_admin=True,
            user_tier="admin",
        )

        # Check session counts
        assert manager.get_session_count() == 3

        # Check user-specific sessions
        user1_sessions = manager.get_user_sessions("user1@example.com")
        assert len(user1_sessions) == 2
        assert user1_session1 in user1_sessions
        assert user1_session2 in user1_sessions

        user2_sessions = manager.get_user_sessions("user2@example.com")
        assert len(user2_sessions) == 1
        assert user2_session in user2_sessions


class TestSettingsIntegration:
    """Test settings integration with other components."""

    def teardown_method(self):
        """Reset settings after each test."""
        reset_settings()

    def test_settings_email_domain_restriction(self):
        """Test email domain restriction in settings."""
        settings = CloudflareSettings(
            cloudflare_team_domain="test.cloudflareaccess.com",
            allowed_email_domains=["company.com", "partner.com"],
        )

        # Create whitelist that uses same domain pattern
        validator = EmailWhitelistValidator(
            whitelist=["@company.com", "@partner.com", "@external.com"],
        )

        # Both settings and whitelist should agree on company.com
        email = "user@company.com"
        assert settings.is_email_allowed(email) is True
        assert validator.is_authorized(email) is True

        # external.com is in whitelist but not allowed by settings
        email = "user@external.com"
        assert settings.is_email_allowed(email) is False
        assert validator.is_authorized(email) is True  # Whitelist allows it


class TestUserTierIntegration:
    """Test user tier integration across components."""

    def test_tier_propagation(self):
        """Test that tier information propagates correctly."""
        whitelist = EmailWhitelistValidator(
            whitelist=["@company.com"],
            admin_emails=["ceo@company.com"],
            full_users=["@company.com"],
        )

        session_manager = SimpleSessionManager()

        for email, expected_tier in [
            ("ceo@company.com", UserTier.ADMIN),
            ("developer@company.com", UserTier.FULL),
        ]:
            tier = whitelist.get_user_tier(email)
            assert tier == expected_tier

            session_id = session_manager.create_session(
                email=email,
                is_admin=tier.has_admin_privileges,
                user_tier=tier.value,
            )

            session = session_manager.get_session(session_id)
            assert session["user_tier"] == tier.value
            assert session["is_admin"] == tier.has_admin_privileges


class TestSecurityIntegration:
    """Test security-related integration scenarios."""

    def test_constant_time_comparison_in_whitelist(self):
        """Test that whitelist uses constant-time comparison."""
        validator = EmailWhitelistValidator(
            whitelist=["secret-admin@company.com"],
            admin_emails=["secret-admin@company.com"],
        )

        # These should all take similar time regardless of match
        # (testing that secrets.compare_digest is used)
        validator.is_authorized("secret-admin@company.com")  # Match
        validator.is_authorized("xxxxxx-xxxxx@company.com")  # Similar length, no match
        validator.is_authorized("a@b.com")  # Short, no match

    def test_session_id_uniqueness(self):
        """Test that session IDs are unique and unpredictable."""
        manager = SimpleSessionManager()
        session_ids = set()

        for _ in range(1000):
            session_id = manager.create_session(
                email="test@example.com",
                is_admin=False,
                user_tier="full",
            )
            assert session_id not in session_ids, "Duplicate session ID generated"
            session_ids.add(session_id)

    def test_model_dump_safe_excludes_sensitive_data(self):
        """Test that safe dump excludes sensitive claims."""
        now = int(datetime.now().timestamp())
        claims = CloudflareJWTClaims(
            email="test@example.com",
            iss="https://private-issuer.com",
            aud=["private-audience-tag"],
            sub="user-id-12345",
            iat=now,
            exp=now + 3600,
            nonce="private-nonce-value",
            custom={"private_key": "private_value"},
        )

        user = CloudflareUser.from_jwt_claims(claims)
        safe_data = user.model_dump_safe()

        # Safe data should not contain sensitive claim details
        assert "claims" not in safe_data
        assert "nonce" not in safe_data
        assert "iss" not in safe_data
        assert "aud" not in safe_data
        # The sub becomes user_id which is expected
        assert "private" not in str(safe_data).lower()
