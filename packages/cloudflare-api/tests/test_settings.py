"""Tests for cloudflare_api settings module."""

import os
from unittest.mock import patch

import pytest
from cloudflare_api.settings import (
    CloudflareAPISettings,
    get_cloudflare_api_settings,
    reset_settings,
)
from pydantic import ValidationError


class TestCloudflareAPISettings:
    """Test suite for CloudflareAPISettings."""

    def test_required_fields_from_env(self, mock_env_vars):
        """Test that required fields are loaded from environment."""
        settings = CloudflareAPISettings()

        assert settings.cloudflare_account_id == "test-account-id-12345"
        assert settings.get_token_value() == "test-api-token-secret"

    def test_missing_required_fields_raises_error(self):
        """Test that missing required fields raise ValidationError."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValidationError):
                CloudflareAPISettings()

    def test_default_values(self, mock_env_vars):
        """Test default configuration values."""
        settings = CloudflareAPISettings()

        assert settings.default_list_kind == "ip"
        assert settings.request_timeout == 30
        assert settings.max_retries == 3
        assert settings.bulk_operation_poll_interval == 1.0
        assert settings.bulk_operation_timeout == 300

    def test_optional_fields_default_to_none(self, mock_env_vars):
        """Test that optional fields default to None."""
        settings = CloudflareAPISettings()

        assert settings.cloudflare_api_email is None
        assert settings.cloudflare_api_key is None
        assert settings.cloudflare_zone_id is None

    def test_list_kind_validation_valid(self, mock_env_vars):
        """Test valid list kind values."""
        for kind in ["ip", "redirect", "hostname", "asn"]:
            with patch.dict(os.environ, {"CF_DEFAULT_LIST_KIND": kind}):
                reset_settings()
                settings = CloudflareAPISettings()
                assert settings.default_list_kind == kind

    def test_list_kind_validation_invalid(self, mock_env_vars):
        """Test that invalid list kind raises error."""
        with patch.dict(os.environ, {"CF_DEFAULT_LIST_KIND": "invalid"}):
            with pytest.raises(ValidationError):
                CloudflareAPISettings()

    def test_list_kind_case_insensitive(self, mock_env_vars):
        """Test that list kind validation is case insensitive."""
        with patch.dict(os.environ, {"CF_DEFAULT_LIST_KIND": "IP"}):
            reset_settings()
            settings = CloudflareAPISettings()
            assert settings.default_list_kind == "ip"

    def test_get_token_value(self, mock_env_vars):
        """Test get_token_value returns plain string."""
        settings = CloudflareAPISettings()
        token = settings.get_token_value()

        assert isinstance(token, str)
        assert token == "test-api-token-secret"

    def test_custom_timeout_values(self, mock_env_vars):
        """Test custom timeout configuration."""
        with patch.dict(
            os.environ,
            {
                "CF_REQUEST_TIMEOUT": "60",
                "CF_BULK_TIMEOUT": "600",
                "CF_BULK_POLL_INTERVAL": "2.5",
            },
        ):
            reset_settings()
            settings = CloudflareAPISettings()

            assert settings.request_timeout == 60
            assert settings.bulk_operation_timeout == 600
            assert settings.bulk_operation_poll_interval == 2.5


class TestGetCloudflareAPISettings:
    """Test suite for get_cloudflare_api_settings function."""

    def test_returns_settings_instance(self, mock_env_vars):
        """Test that get_cloudflare_api_settings returns settings."""
        settings = get_cloudflare_api_settings()

        assert isinstance(settings, CloudflareAPISettings)

    def test_returns_singleton(self, mock_env_vars):
        """Test that get_cloudflare_api_settings returns same instance."""
        settings1 = get_cloudflare_api_settings()
        settings2 = get_cloudflare_api_settings()

        assert settings1 is settings2

    def test_reset_creates_new_instance(self, mock_env_vars):
        """Test that reset_settings allows new instance creation."""
        settings1 = get_cloudflare_api_settings()
        reset_settings()
        settings2 = get_cloudflare_api_settings()

        assert settings1 is not settings2
