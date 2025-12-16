"""Configuration models for IP range groups.

Defines the schema for IP group configuration files.
"""

from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class SourceType(str, Enum):
    """Types of IP sources."""

    STATIC = "static"  # Hardcoded IP list
    URL = "url"  # Generic URL returning IP list
    GITHUB = "github"  # GitHub Meta API
    GOOGLE_CLOUD = "google_cloud"  # Google Cloud IP ranges
    AWS = "aws"  # AWS IP ranges
    AZURE = "azure"  # Azure IP ranges
    CLOUDFLARE = "cloudflare"  # Cloudflare's own IPs


class IPSourceConfig(BaseModel):
    """Configuration for an IP source.

    Attributes:
        type: Type of IP source
        ips: Static list of IPs (for static type)
        url: URL to fetch IPs from (for url type)
        services: Filter by service names (for provider types)
        regions: Filter by regions (for provider types)
        ip_version: Filter by IP version (4 or 6, or both if None)
    """

    type: SourceType = Field(description="Type of IP source")
    ips: list[str] = Field(default_factory=list, description="Static IP list")
    url: str | None = Field(default=None, description="URL to fetch IPs")
    services: list[str] = Field(
        default_factory=list, description="Service filter (e.g., 'actions', 'hooks')"
    )
    regions: list[str] = Field(
        default_factory=list, description="Region filter (e.g., 'us-east1')"
    )
    ip_version: int | None = Field(
        default=None, description="IP version filter (4, 6, or None for both)"
    )
    json_path: str | None = Field(
        default=None, description="JSONPath to extract IPs from response"
    )

    @field_validator("ip_version")
    @classmethod
    def validate_ip_version(cls, v: int | None) -> int | None:
        """Validate IP version is 4 or 6."""
        if v is not None and v not in (4, 6):
            msg = "ip_version must be 4 or 6"
            raise ValueError(msg)
        return v


class IPGroupConfig(BaseModel):
    """Configuration for an IP range group.

    Attributes:
        name: Human-readable name for the group
        cloudflare_list_name: Name of the Cloudflare list to sync to
        description: Optional description
        sources: List of IP sources that make up this group
        enabled: Whether this group is enabled for syncing
        tags: Optional tags for categorization
    """

    name: str = Field(description="Human-readable name")
    cloudflare_list_name: str = Field(description="Cloudflare list name to sync to")
    description: str | None = Field(default=None, description="Optional description")
    sources: list[IPSourceConfig] = Field(
        default_factory=list, description="IP sources"
    )
    enabled: bool = Field(default=True, description="Whether syncing is enabled")
    tags: list[str] = Field(default_factory=list, description="Optional tags")


class IPGroupsConfig(BaseModel):
    """Root configuration for all IP groups.

    Attributes:
        version: Config schema version
        groups: List of IP group configurations
        defaults: Default settings for all groups
    """

    version: str = Field(default="1.0", description="Config schema version")
    groups: list[IPGroupConfig] = Field(
        default_factory=list, description="IP group configurations"
    )
    cache_ttl_seconds: int = Field(
        default=3600, description="How long to cache fetched IPs"
    )
    cloudflare_list_prefix: str = Field(
        default="", description="Prefix for all Cloudflare list names"
    )


def load_config(path: str | Path) -> IPGroupsConfig:
    """Load IP groups configuration from a YAML file.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        Parsed configuration.

    Raises:
        FileNotFoundError: If the config file doesn't exist.
        ValueError: If the config is invalid.
    """
    path = Path(path)
    if not path.exists():
        msg = f"Config file not found: {path}"
        raise FileNotFoundError(msg)

    with path.open() as f:
        data: dict[str, Any] = yaml.safe_load(f)

    return IPGroupsConfig.model_validate(data)
