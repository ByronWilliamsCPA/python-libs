"""Cloudflare API configuration settings.

Environment-based configuration for Cloudflare API authentication and defaults.
"""


from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CloudflareAPISettings(BaseSettings):
    """Configuration for Cloudflare API client.

    All settings can be configured via environment variables or .env file.

    Attributes:
        cloudflare_api_token: API token with appropriate permissions
        cloudflare_account_id: Cloudflare account identifier
        cloudflare_api_email: Optional email for legacy API key auth
        cloudflare_api_key: Optional global API key (legacy)
        default_list_kind: Default kind for new IP lists (ip, redirect, hostname, asn)
        request_timeout: HTTP request timeout in seconds
        max_retries: Maximum number of retries for failed requests
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    # Required authentication
    cloudflare_api_token: SecretStr = Field(
        ...,
        alias="CLOUDFLARE_API_TOKEN",
        description="Cloudflare API token with required permissions",
    )
    cloudflare_account_id: str = Field(
        ...,
        alias="CLOUDFLARE_ACCOUNT_ID",
        description="Cloudflare account identifier",
    )

    # Optional legacy authentication (prefer API token)
    cloudflare_api_email: str | None = Field(
        default=None,
        alias="CLOUDFLARE_API_EMAIL",
        description="Email for legacy API key authentication",
    )
    cloudflare_api_key: SecretStr | None = Field(
        default=None,
        alias="CLOUDFLARE_API_KEY",
        description="Global API key (legacy, prefer API token)",
    )

    # Optional zone-level operations
    cloudflare_zone_id: str | None = Field(
        default=None,
        alias="CLOUDFLARE_ZONE_ID",
        description="Default zone ID for zone-scoped operations",
    )

    # Client configuration
    default_list_kind: str = Field(
        default="ip",
        alias="CF_DEFAULT_LIST_KIND",
        description="Default kind for new lists (ip, redirect, hostname, asn)",
    )
    request_timeout: int = Field(
        default=30,
        alias="CF_REQUEST_TIMEOUT",
        description="HTTP request timeout in seconds",
    )
    max_retries: int = Field(
        default=3,
        alias="CF_MAX_RETRIES",
        description="Maximum retries for failed requests",
    )

    # Bulk operation settings
    bulk_operation_poll_interval: float = Field(
        default=1.0,
        alias="CF_BULK_POLL_INTERVAL",
        description="Seconds between bulk operation status checks",
    )
    bulk_operation_timeout: int = Field(
        default=300,
        alias="CF_BULK_TIMEOUT",
        description="Maximum seconds to wait for bulk operations",
    )

    @field_validator("default_list_kind")
    @classmethod
    def validate_list_kind(cls, v: str) -> str:
        """Validate list kind is a supported type."""
        valid_kinds = {"ip", "redirect", "hostname", "asn"}
        if v.lower() not in valid_kinds:
            msg = f"Invalid list kind: {v}. Must be one of: {', '.join(valid_kinds)}"
            raise ValueError(msg)
        return v.lower()

    def get_token_value(self) -> str:
        """Get the API token as a plain string.

        Returns:
            The API token value.
        """
        return self.cloudflare_api_token.get_secret_value()


_settings_instance: CloudflareAPISettings | None = None


def get_cloudflare_api_settings() -> CloudflareAPISettings:
    """Get default settings (singleton, reads from environment).

    Returns:
        CloudflareAPISettings instance.

    Raises:
        ValidationError: If required environment variables are missing.
    """
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = CloudflareAPISettings()
    return _settings_instance


def reset_settings() -> None:
    """Reset singleton (for testing)."""
    global _settings_instance
    _settings_instance = None
