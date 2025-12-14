"""Configuration settings for Cloudflare Access authentication.

This module provides Pydantic Settings for configuring Cloudflare Access
authentication middleware.

Environment Variables:
    CLOUDFLARE_TEAM_DOMAIN: Your Cloudflare Access team domain
    CLOUDFLARE_AUDIENCE_TAG: Application audience tag from Cloudflare dashboard
    CLOUDFLARE_ENABLED: Enable/disable Cloudflare authentication (default: True)
    CLOUDFLARE_JWT_HEADER: Header name for JWT token (default: Cf-Access-Jwt-Assertion)
    CLOUDFLARE_EMAIL_HEADER: Header name for email (default: Cf-Access-Authenticated-User-Email)

Example:
    from cloudflare_auth.config import get_cloudflare_settings

    settings = get_cloudflare_settings()
    print(f"Team domain: {settings.cloudflare_team_domain}")
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CloudflareSettings(BaseSettings):
    """Configuration for Cloudflare Access authentication.

    This class uses Pydantic Settings to load configuration from environment
    variables with sensible defaults for development.

    Attributes:
        cloudflare_team_domain: Cloudflare Access team domain (e.g., "myteam")
        cloudflare_audience_tag: Application audience tag from CF dashboard
        cloudflare_enabled: Whether CF authentication is enabled
        jwt_header_name: Header containing the JWT token
        email_header_name: Header containing the authenticated email
        jwt_algorithm: Algorithm for JWT validation (default: RS256)
        jwt_cache_max_keys: Maximum cached signing keys
        require_email_verification: Require email claim in token
        log_auth_failures: Log failed authentication attempts
        require_cloudflare_headers: Require CF-Ray header for validation
        allowed_tunnel_ips: List of allowed tunnel IPs (optional)
        allowed_email_domains: Restrict to specific email domains
        cookie_path: Session cookie path
        cookie_secure: Use secure cookies
        cookie_samesite: Cookie SameSite attribute
        cookie_domain: Cookie domain (optional)
    """

    model_config = SettingsConfigDict(
        env_prefix="CLOUDFLARE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core settings
    cloudflare_team_domain: str = Field(
        default="",
        description="Cloudflare Access team domain",
    )
    cloudflare_audience_tag: str = Field(
        default="",
        description="Application audience tag from Cloudflare dashboard",
    )
    cloudflare_enabled: bool = Field(
        default=True,
        alias="CLOUDFLARE_ENABLED",
        description="Enable Cloudflare authentication",
    )

    # Header names
    jwt_header_name: str = Field(
        default="Cf-Access-Jwt-Assertion",
        alias="CLOUDFLARE_JWT_HEADER",
        description="Header containing JWT token",
    )
    email_header_name: str = Field(
        default="Cf-Access-Authenticated-User-Email",
        alias="CLOUDFLARE_EMAIL_HEADER",
        description="Header containing authenticated email",
    )

    # JWT settings
    jwt_algorithm: str = Field(
        default="RS256",
        description="JWT signing algorithm",
    )
    jwt_cache_max_keys: int = Field(
        default=16,
        description="Maximum number of cached signing keys",
    )

    # Validation settings
    require_email_verification: bool = Field(
        default=True,
        description="Require email claim in JWT",
    )
    log_auth_failures: bool = Field(
        default=True,
        description="Log failed authentication attempts",
    )
    require_cloudflare_headers: bool = Field(
        default=False,
        description="Require CF-Ray header for validation",
    )

    # IP restrictions
    allowed_tunnel_ips: list[str] = Field(
        default_factory=list,
        description="List of allowed tunnel IPs",
    )

    # Email domain restrictions
    allowed_email_domains: list[str] = Field(
        default_factory=list,
        description="Restrict to specific email domains",
    )

    # Cookie settings
    cookie_path: str = Field(default="/", description="Session cookie path")
    cookie_secure: bool = Field(default=True, description="Use secure cookies")
    cookie_samesite: Literal["lax", "strict", "none"] = Field(
        default="lax",
        description="Cookie SameSite attribute",
    )
    cookie_domain: str | None = Field(
        default=None,
        description="Cookie domain",
    )

    @field_validator("allowed_tunnel_ips", "allowed_email_domains", mode="before")
    @classmethod
    def parse_comma_separated(cls, v: str | list[str] | None) -> list[str]:
        """Parse comma-separated strings into lists."""
        if v is None:
            return []
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    @property
    def certs_url(self) -> str | None:
        """Get the Cloudflare certificate URL.

        Returns:
            URL for JWKS endpoint, or None if team domain not configured.
        """
        if not self.cloudflare_team_domain:
            return None
        return f"https://{self.cloudflare_team_domain}.cloudflareaccess.com/cdn-cgi/access/certs"

    @property
    def issuer(self) -> str | None:
        """Get the expected token issuer.

        Returns:
            Issuer URL, or None if team domain not configured.
        """
        if not self.cloudflare_team_domain:
            return None
        return f"https://{self.cloudflare_team_domain}.cloudflareaccess.com"

    def is_email_allowed(self, email: str) -> bool:
        """Check if an email address is allowed.

        Args:
            email: Email address to check

        Returns:
            True if email is allowed (no restrictions or matches allowed domains)
        """
        if not self.allowed_email_domains:
            return True

        email_domain = email.split("@")[-1].lower() if "@" in email else ""
        return any(
            email_domain == domain.lower().lstrip("@")
            for domain in self.allowed_email_domains
        )


@lru_cache
def get_cloudflare_settings() -> CloudflareSettings:
    """Get cached Cloudflare settings instance.

    This function returns a cached settings instance for efficiency.
    Settings are loaded from environment variables and .env file.

    Returns:
        CloudflareSettings instance

    Example:
        settings = get_cloudflare_settings()
        if settings.cloudflare_enabled:
            # Configure middleware
            pass
    """
    return CloudflareSettings()


def clear_settings_cache() -> None:
    """Clear the cached settings.

    Use this when you need to reload settings, such as after
    modifying environment variables in tests.
    """
    get_cloudflare_settings.cache_clear()
