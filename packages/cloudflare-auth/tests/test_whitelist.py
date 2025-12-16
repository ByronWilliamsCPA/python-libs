"""Tests for cloudflare_auth whitelist module."""

import pytest

from cloudflare_auth.whitelist import (
    EmailWhitelistConfig,
    EmailWhitelistValidator,
    UserTier,
    WhitelistManager,
    create_validator_from_env,
)


class TestUserTier:
    """Test suite for UserTier enum."""

    def test_from_string_admin(self):
        """Test creating ADMIN tier from string."""
        tier = UserTier.from_string("admin")
        assert tier == UserTier.ADMIN

    def test_from_string_full(self):
        """Test creating FULL tier from string."""
        tier = UserTier.from_string("full")
        assert tier == UserTier.FULL

    def test_from_string_limited(self):
        """Test creating LIMITED tier from string."""
        tier = UserTier.from_string("limited")
        assert tier == UserTier.LIMITED

    def test_from_string_case_insensitive(self):
        """Test that from_string is case insensitive."""
        assert UserTier.from_string("ADMIN") == UserTier.ADMIN
        assert UserTier.from_string("Full") == UserTier.FULL
        assert UserTier.from_string("LIMITED") == UserTier.LIMITED

    def test_from_string_invalid(self):
        """Test that invalid tier raises ValueError."""
        with pytest.raises(ValueError, match="Invalid user tier"):
            UserTier.from_string("invalid")

    def test_can_access_premium_models_admin(self):
        """Test admin can access premium models."""
        assert UserTier.ADMIN.can_access_premium_models is True

    def test_can_access_premium_models_full(self):
        """Test full tier can access premium models."""
        assert UserTier.FULL.can_access_premium_models is True

    def test_can_access_premium_models_limited(self):
        """Test limited tier cannot access premium models."""
        assert UserTier.LIMITED.can_access_premium_models is False

    def test_has_admin_privileges(self):
        """Test has_admin_privileges property."""
        assert UserTier.ADMIN.has_admin_privileges is True
        assert UserTier.FULL.has_admin_privileges is False
        assert UserTier.LIMITED.has_admin_privileges is False


class TestEmailWhitelistConfig:
    """Test suite for EmailWhitelistConfig."""

    def test_default_values(self):
        """Test default configuration values."""
        config = EmailWhitelistConfig()

        assert config.whitelist == []
        assert config.admin_emails == []
        assert config.full_users == []
        assert config.limited_users == []
        assert config.case_sensitive is False

    def test_normalize_emails_from_string(self):
        """Test normalizing emails from comma-separated string."""
        config = EmailWhitelistConfig(
            whitelist="user1@example.com, user2@example.com, @company.com"
        )

        assert len(config.whitelist) == 3
        assert "user1@example.com" in config.whitelist
        assert "user2@example.com" in config.whitelist
        assert "@company.com" in config.whitelist

    def test_normalize_emails_from_list(self):
        """Test normalizing emails from list."""
        config = EmailWhitelistConfig(
            whitelist=["User1@Example.com", "User2@Example.com"]
        )

        assert "user1@example.com" in config.whitelist
        assert "user2@example.com" in config.whitelist


class TestEmailWhitelistValidator:
    """Test suite for EmailWhitelistValidator."""

    @pytest.fixture
    def validator(self):
        """Create a sample validator for testing."""
        return EmailWhitelistValidator(
            whitelist=["user@example.com", "@company.com"],
            admin_emails=["admin@company.com"],
            full_users=["@company.com"],
            limited_users=["contractor@external.com"],
        )

    def test_is_authorized_individual_email(self, validator):
        """Test authorization for individual email."""
        assert validator.is_authorized("user@example.com") is True

    def test_is_authorized_domain_pattern(self, validator):
        """Test authorization for domain pattern."""
        assert validator.is_authorized("anyone@company.com") is True
        assert validator.is_authorized("newuser@company.com") is True

    def test_is_authorized_unauthorized_email(self, validator):
        """Test that unauthorized emails are rejected."""
        assert validator.is_authorized("unknown@other.com") is False

    def test_is_authorized_empty_email(self, validator):
        """Test that empty email is not authorized."""
        assert validator.is_authorized("") is False
        assert validator.is_authorized(None) is False

    def test_is_authorized_case_insensitive(self):
        """Test case insensitive matching."""
        validator = EmailWhitelistValidator(
            whitelist=["User@Example.com"],
            case_sensitive=False,
        )

        assert validator.is_authorized("user@example.com") is True
        assert validator.is_authorized("USER@EXAMPLE.COM") is True

    def test_is_admin(self, validator):
        """Test admin detection."""
        assert validator.is_admin("admin@company.com") is True
        assert validator.is_admin("user@example.com") is False
        assert validator.is_admin("random@company.com") is False

    def test_is_admin_empty_email(self, validator):
        """Test that empty email is not admin."""
        assert validator.is_admin("") is False

    def test_get_user_role(self, validator):
        """Test get_user_role method."""
        assert validator.get_user_role("admin@company.com") == "admin"
        assert validator.get_user_role("user@example.com") == "user"
        assert validator.get_user_role("unknown@other.com") == "unauthorized"

    def test_get_user_tier_admin(self, validator):
        """Test tier detection for admin."""
        tier = validator.get_user_tier("admin@company.com")
        assert tier == UserTier.ADMIN

    def test_get_user_tier_full(self, validator):
        """Test tier detection for full users."""
        tier = validator.get_user_tier("someone@company.com")
        assert tier == UserTier.FULL

    def test_get_user_tier_limited(self, validator):
        """Test tier detection for limited users."""
        validator2 = EmailWhitelistValidator(
            whitelist=["contractor@external.com"],
            limited_users=["contractor@external.com"],
        )
        tier = validator2.get_user_tier("contractor@external.com")
        assert tier == UserTier.LIMITED

    def test_get_user_tier_unauthorized(self, validator):
        """Test tier detection for unauthorized email."""
        with pytest.raises(ValueError, match="not authorized"):
            validator.get_user_tier("unknown@other.com")

    def test_get_user_tier_empty_email(self, validator):
        """Test tier detection for empty email."""
        with pytest.raises(ValueError, match="cannot be empty"):
            validator.get_user_tier("")

    def test_can_access_premium_models(self, validator):
        """Test premium model access checking."""
        assert validator.can_access_premium_models("admin@company.com") is True
        assert validator.can_access_premium_models("someone@company.com") is True
        assert validator.can_access_premium_models("unknown@other.com") is False

    def test_has_admin_privileges(self, validator):
        """Test admin privilege checking."""
        assert validator.has_admin_privileges("admin@company.com") is True
        assert validator.has_admin_privileges("someone@company.com") is False

    def test_get_whitelist_stats(self, validator):
        """Test whitelist statistics."""
        stats = validator.get_whitelist_stats()

        assert "individual_emails" in stats
        assert "domain_patterns" in stats
        assert "admin_emails" in stats
        assert "total_entries" in stats
        assert "tier_distribution" in stats

    def test_validate_whitelist_config_warnings(self):
        """Test configuration validation warnings."""
        validator = EmailWhitelistValidator(
            whitelist=["@company.com"],
            admin_emails=["admin@other.com"],  # Not in whitelist
        )
        warnings = validator.validate_whitelist_config()

        assert len(warnings) > 0
        assert any("not in whitelist" in w for w in warnings)

    def test_validate_whitelist_config_public_domains(self):
        """Test warning for public email domains."""
        validator = EmailWhitelistValidator(
            whitelist=["@gmail.com"],
        )
        warnings = validator.validate_whitelist_config()

        assert any("gmail.com" in w for w in warnings)


class TestWhitelistManager:
    """Test suite for WhitelistManager."""

    @pytest.fixture
    def manager(self):
        """Create a manager with a sample validator."""
        validator = EmailWhitelistValidator(
            whitelist=["user@example.com"],
        )
        return WhitelistManager(validator)

    def test_add_email(self, manager):
        """Test adding email to whitelist."""
        result = manager.add_email("newuser@test.com")

        assert result is True
        assert manager.validator.is_authorized("newuser@test.com") is True

    def test_add_domain_pattern(self, manager):
        """Test adding domain pattern."""
        result = manager.add_email("@newdomain.com")

        assert result is True
        assert manager.validator.is_authorized("anyone@newdomain.com") is True

    def test_add_email_as_admin(self, manager):
        """Test adding email with admin privileges."""
        result = manager.add_email("admin@test.com", is_admin=True)

        assert result is True
        assert manager.validator.is_admin("admin@test.com") is True

    def test_add_email_invalid_format(self, manager):
        """Test adding invalid email format."""
        with pytest.raises(ValueError, match="Invalid email format"):
            manager.add_email("invalid-email")

    def test_add_email_empty(self, manager):
        """Test adding empty email."""
        with pytest.raises(ValueError, match="cannot be empty"):
            manager.add_email("")

    def test_remove_email(self, manager):
        """Test removing email from whitelist."""
        result = manager.remove_email("user@example.com")

        assert result is True
        assert manager.validator.is_authorized("user@example.com") is False

    def test_remove_email_not_found(self, manager):
        """Test removing non-existent email."""
        result = manager.remove_email("nonexistent@test.com")

        assert result is False

    def test_check_email(self, manager):
        """Test checking email status."""
        status = manager.check_email("user@example.com")

        assert status["is_authorized"] is True
        assert "email" in status
        assert "is_admin" in status
        assert "role" in status


class TestCreateValidatorFromEnv:
    """Test suite for create_validator_from_env function."""

    def test_create_from_comma_separated(self):
        """Test creating validator from comma-separated strings."""
        validator = create_validator_from_env(
            whitelist_str="user@example.com,@company.com",
            admin_emails_str="admin@company.com",
            full_users_str="@company.com",
        )

        assert validator.is_authorized("user@example.com") is True
        assert validator.is_authorized("anyone@company.com") is True
        assert validator.is_admin("admin@company.com") is True

    def test_create_with_empty_strings(self):
        """Test creating validator with empty strings."""
        validator = create_validator_from_env(
            whitelist_str="",
            admin_emails_str="",
        )

        assert validator.is_authorized("anyone@test.com") is False

    def test_create_with_whitespace(self):
        """Test handling of whitespace in input."""
        validator = create_validator_from_env(
            whitelist_str="  user@example.com  ,  @company.com  ",
        )

        assert validator.is_authorized("user@example.com") is True
        assert validator.is_authorized("anyone@company.com") is True
