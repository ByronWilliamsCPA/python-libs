"""Cloudflare Access configuration settings.

Hybrid approach: reads from environment by default, but accepts injected settings.
"""


from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CloudflareSettings(BaseSettings):
    """Configuration for Cloudflare Access authentication."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    # Required
    cloudflare_team_domain: str = Field(default="", alias="CLOUDFLARE_TEAM_DOMAIN")
    cloudflare_audience_tag: str = Field(default="", alias="CLOUDFLARE_AUDIENCE_TAG")
    cloudflare_enabled: bool = Field(default=True, alias="CLOUDFLARE_ENABLED")

    # Headers
    jwt_header_name: str = Field(
        default="Cf-Access-Jwt-Assertion", alias="CF_JWT_HEADER"
    )
    email_header_name: str = Field(
        default="Cf-Access-Authenticated-User-Email", alias="CF_EMAIL_HEADER"
    )

    # Security
    require_email_verification: bool = Field(
        default=True, alias="CF_REQUIRE_EMAIL_VERIFICATION"
    )
    log_auth_failures: bool = Field(default=True, alias="CF_LOG_AUTH_FAILURES")
    require_cloudflare_headers: bool = Field(
        default=True, alias="CF_REQUIRE_CLOUDFLARE_HEADERS"
    )

    # Access control
    allowed_email_domains: list[str] = Field(
        default_factory=list, alias="CF_ALLOWED_EMAIL_DOMAINS"
    )
    allowed_tunnel_ips: list[str] = Field(
        default_factory=list, alias="CF_ALLOWED_TUNNEL_IPS"
    )

    # Cookies
    cookie_domain: str | None = Field(default=None, alias="CF_COOKIE_DOMAIN")
    cookie_path: str = Field(default="/", alias="CF_COOKIE_PATH")
    cookie_secure: bool = Field(default=True, alias="CF_COOKIE_SECURE")
    cookie_samesite: str = Field(default="lax", alias="CF_COOKIE_SAMESITE")

    # JWT
    jwt_algorithm: str = Field(default="RS256", alias="CF_JWT_ALGORITHM")
    jwt_cache_max_keys: int = Field(default=16, alias="CF_JWT_CACHE_MAX_KEYS")

    @field_validator("allowed_email_domains", "allowed_tunnel_ips", mode="before")
    @classmethod
    def parse_comma_separated(cls, v: str | list[str] | None) -> list[str]:
        """Parse comma-separated string into list."""
        if isinstance(v, str):
            return (
                [item.strip() for item in v.split(",") if item.strip()]
                if v.strip()
                else []
            )
        return v or []

    @property
    def issuer(self) -> str:
        """Get the Cloudflare issuer URL."""
        if not self.cloudflare_team_domain:
            return ""
        domain = self.cloudflare_team_domain.rstrip("/")
        return f"https://{domain}" if not domain.startswith("https://") else domain

    @property
    def certs_url(self) -> str:
        """Get the Cloudflare certs URL."""
        return f"{self.issuer}/cdn-cgi/access/certs" if self.issuer else ""

    def is_email_allowed(self, email: str) -> bool:
        """Check if an email is allowed based on domain restrictions."""
        if not self.allowed_email_domains:
            return True
        if "@" not in email:
            return False
        domain = email.split("@")[-1].lower()
        return domain in [d.lower() for d in self.allowed_email_domains]


_settings_instance: CloudflareSettings | None = None


def get_cloudflare_settings() -> CloudflareSettings:
    """Get default settings (singleton, reads from environment)."""
    global _settings_instance  # noqa: PLW0603
    if _settings_instance is None:
        _settings_instance = CloudflareSettings()
    return _settings_instance


def reset_settings() -> None:
    """Reset singleton (for testing)."""
    global _settings_instance  # noqa: PLW0603
    _settings_instance = None
