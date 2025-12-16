"""Tests for cloudflare_auth settings module."""

import os
from unittest.mock import patch

from cloudflare_auth.settings import (
    CloudflareSettings,
    get_cloudflare_settings,
    reset_settings,
)


class TestCloudflareSettings:
    """Test suite for CloudflareSettings."""

    def test_default_values(self):
        """Test default configuration values."""
        settings = CloudflareSettings()

        assert settings.cloudflare_team_domain == ""
        assert settings.cloudflare_audience_tag == ""
        assert settings.cloudflare_enabled is True
        assert settings.jwt_header_name == "Cf-Access-Jwt-Assertion"
        assert settings.email_header_name == "Cf-Access-Authenticated-User-Email"

    def test_security_defaults(self):
        """Test security-related defaults."""
        settings = CloudflareSettings()

        assert settings.require_email_verification is True
        assert settings.log_auth_failures is True
        assert settings.require_cloudflare_headers is True
        assert settings.cookie_secure is True

    def test_jwt_defaults(self):
        """Test JWT-related defaults."""
        settings = CloudflareSettings()

        assert settings.jwt_algorithm == "RS256"
        assert settings.jwt_cache_max_keys == 16

    def test_cookie_defaults(self):
        """Test cookie-related defaults."""
        settings = CloudflareSettings()

        assert settings.cookie_domain is None
        assert settings.cookie_path == "/"
        assert settings.cookie_samesite == "lax"

    def test_issuer_property_empty(self):
        """Test issuer property with empty domain."""
        settings = CloudflareSettings()

        assert settings.issuer == ""

    def test_issuer_property_with_domain(self):
        """Test issuer property with domain."""
        settings = CloudflareSettings(
            cloudflare_team_domain="myteam.cloudflareaccess.com"
        )

        assert settings.issuer == "https://myteam.cloudflareaccess.com"

    def test_issuer_property_with_https_prefix(self):
        """Test issuer property when domain already has https."""
        settings = CloudflareSettings(
            cloudflare_team_domain="https://myteam.cloudflareaccess.com"
        )

        assert settings.issuer == "https://myteam.cloudflareaccess.com"

    def test_certs_url_property_empty(self):
        """Test certs_url property with empty domain."""
        settings = CloudflareSettings()

        assert settings.certs_url == ""

    def test_certs_url_property_with_domain(self):
        """Test certs_url property with domain."""
        settings = CloudflareSettings(
            cloudflare_team_domain="myteam.cloudflareaccess.com"
        )

        assert (
            settings.certs_url
            == "https://myteam.cloudflareaccess.com/cdn-cgi/access/certs"
        )

    def test_parse_comma_separated_domains(self):
        """Test parsing comma-separated email domains."""
        settings = CloudflareSettings(allowed_email_domains="example.com,company.com")

        assert settings.allowed_email_domains == ["example.com", "company.com"]

    def test_parse_comma_separated_empty(self):
        """Test parsing empty comma-separated string."""
        settings = CloudflareSettings(allowed_email_domains="")

        assert settings.allowed_email_domains == []

    def test_parse_comma_separated_list(self):
        """Test that list input is preserved."""
        settings = CloudflareSettings(
            allowed_email_domains=["example.com", "company.com"]
        )

        assert settings.allowed_email_domains == ["example.com", "company.com"]

    def test_is_email_allowed_no_restrictions(self):
        """Test is_email_allowed with no domain restrictions."""
        settings = CloudflareSettings()

        assert settings.is_email_allowed("anyone@anywhere.com") is True

    def test_is_email_allowed_with_restrictions(self):
        """Test is_email_allowed with domain restrictions."""
        settings = CloudflareSettings(allowed_email_domains=["company.com"])

        assert settings.is_email_allowed("user@company.com") is True
        assert settings.is_email_allowed("user@other.com") is False

    def test_is_email_allowed_case_insensitive(self):
        """Test is_email_allowed is case insensitive."""
        settings = CloudflareSettings(allowed_email_domains=["Company.Com"])

        assert settings.is_email_allowed("user@company.com") is True
        assert settings.is_email_allowed("user@COMPANY.COM") is True

    def test_is_email_allowed_invalid_email(self):
        """Test is_email_allowed with invalid email format."""
        settings = CloudflareSettings(allowed_email_domains=["company.com"])

        assert settings.is_email_allowed("invalid-no-at-sign") is False

    @patch.dict(os.environ, {"CLOUDFLARE_TEAM_DOMAIN": "env-team.cloudflareaccess.com"})
    def test_from_environment(self):
        """Test loading settings from environment."""
        settings = CloudflareSettings()

        assert settings.cloudflare_team_domain == "env-team.cloudflareaccess.com"


class TestGetCloudflareSettings:
    """Test suite for get_cloudflare_settings function."""

    def teardown_method(self):
        """Reset settings after each test."""
        reset_settings()

    def test_returns_settings_instance(self):
        """Test that get_cloudflare_settings returns a CloudflareSettings instance."""
        settings = get_cloudflare_settings()

        assert isinstance(settings, CloudflareSettings)

    def test_returns_singleton(self):
        """Test that get_cloudflare_settings returns the same instance."""
        settings1 = get_cloudflare_settings()
        settings2 = get_cloudflare_settings()

        assert settings1 is settings2

    def test_reset_creates_new_instance(self):
        """Test that reset_settings allows new instance creation."""
        settings1 = get_cloudflare_settings()
        reset_settings()
        settings2 = get_cloudflare_settings()

        # They should be different objects after reset
        assert settings1 is not settings2


class TestResetSettings:
    """Test suite for reset_settings function."""

    def test_reset_clears_singleton(self):
        """Test that reset_settings clears the singleton."""
        # Get initial settings
        _ = get_cloudflare_settings()

        # Reset
        reset_settings()

        # Get new settings - should create new instance
        settings = get_cloudflare_settings()
        assert isinstance(settings, CloudflareSettings)
