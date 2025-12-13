"""IP fetchers for various sources.

Fetchers retrieve IP ranges from static lists, URLs, or cloud provider APIs.
"""

import ipaddress
import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Any

import httpx

from cloudflare_api.ip_groups.config import IPSourceConfig, SourceType

logger = logging.getLogger(__name__)

# Known provider URLs
GITHUB_META_URL = "https://api.github.com/meta"
GOOGLE_CLOUD_URL = "https://www.gstatic.com/ipranges/cloud.json"
AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
AZURE_IP_RANGES_URL = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPV6_URL = "https://www.cloudflare.com/ips-v6"


class IPFetcher(ABC):
    """Base class for IP fetchers."""

    @abstractmethod
    def fetch(self, config: IPSourceConfig) -> list[str]:
        """Fetch IP ranges from the source.

        Args:
            config: Source configuration.

        Returns:
            List of IP addresses or CIDR ranges.
        """

    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate an IP address or CIDR range.

        Args:
            ip: IP address or CIDR to validate.

        Returns:
            True if valid, False otherwise.
        """
        try:
            # Try as network (CIDR)
            ipaddress.ip_network(ip, strict=False)
            return True
        except ValueError:
            try:
                # Try as single address
                ipaddress.ip_address(ip)
                return True
            except ValueError:
                return False

    @staticmethod
    def get_ip_version(ip: str) -> int:
        """Get the IP version (4 or 6) of an address.

        Args:
            ip: IP address or CIDR.

        Returns:
            4 or 6.
        """
        try:
            network = ipaddress.ip_network(ip, strict=False)
            return network.version
        except ValueError:
            address = ipaddress.ip_address(ip.split("/")[0])
            return address.version

    def filter_by_version(self, ips: list[str], version: int | None) -> list[str]:
        """Filter IPs by version.

        Args:
            ips: List of IP addresses.
            version: IP version to filter by (4, 6, or None for all).

        Returns:
            Filtered list of IPs.
        """
        if version is None:
            return ips
        return [ip for ip in ips if self.get_ip_version(ip) == version]


class StaticIPFetcher(IPFetcher):
    """Fetcher for static IP lists."""

    def fetch(self, config: IPSourceConfig) -> list[str]:
        """Return the static IP list from config.

        Args:
            config: Source configuration with static IPs.

        Returns:
            List of validated IP addresses.
        """
        valid_ips = []
        for ip in config.ips:
            if self.validate_ip(ip):
                valid_ips.append(ip)
            else:
                logger.warning("Invalid IP address: %s", ip)

        return self.filter_by_version(valid_ips, config.ip_version)


class URLIPFetcher(IPFetcher):
    """Fetcher for generic URL sources."""

    def __init__(self, timeout: float = 30.0) -> None:
        """Initialize the URL fetcher.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        self.timeout = timeout

    def fetch(self, config: IPSourceConfig) -> list[str]:
        """Fetch IPs from a URL.

        Args:
            config: Source configuration with URL.

        Returns:
            List of IP addresses extracted from the response.

        Raises:
            ValueError: If URL is not configured.
            httpx.HTTPError: If the request fails.
        """
        if not config.url:
            msg = "URL is required for URL source type"
            raise ValueError(msg)

        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(config.url)
            response.raise_for_status()

        content_type = response.headers.get("content-type", "")

        if "json" in content_type:
            return self._parse_json(response.text, config)
        else:
            return self._parse_text(response.text, config)

    def _parse_json(self, text: str, config: IPSourceConfig) -> list[str]:
        """Parse JSON response for IPs.

        Args:
            text: JSON response text.
            config: Source configuration.

        Returns:
            List of IP addresses.
        """
        data = json.loads(text)

        if config.json_path:
            # Simple JSONPath-like extraction
            ips = self._extract_json_path(data, config.json_path)
        else:
            # Try to auto-detect IP fields
            ips = self._auto_extract_ips(data)

        valid_ips = [ip for ip in ips if self.validate_ip(ip)]
        return self.filter_by_version(valid_ips, config.ip_version)

    def _parse_text(self, text: str, config: IPSourceConfig) -> list[str]:
        """Parse plain text response for IPs.

        Args:
            text: Plain text response.
            config: Source configuration.

        Returns:
            List of IP addresses (one per line).
        """
        ips = []
        for line in text.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                if self.validate_ip(line):
                    ips.append(line)

        return self.filter_by_version(ips, config.ip_version)

    def _extract_json_path(self, data: Any, path: str) -> list[str]:
        """Extract values from JSON using a simple path.

        Supports paths like "prefixes[*].ip_prefix" or "hooks".

        Args:
            data: Parsed JSON data.
            path: JSONPath-like expression.

        Returns:
            List of extracted string values.
        """
        parts = path.split(".")
        current = data

        for part in parts:
            if "[*]" in part:
                # Array access
                key = part.replace("[*]", "")
                if key:
                    current = current.get(key, [])
                if isinstance(current, list):
                    # Continue with remaining path on each element
                    remaining = ".".join(parts[parts.index(part) + 1:])
                    if remaining:
                        results = []
                        for item in current:
                            results.extend(self._extract_json_path(item, remaining))
                        return results
                    else:
                        return [str(item) for item in current if item]
            elif isinstance(current, dict):
                current = current.get(part, {})
            else:
                return []

        if isinstance(current, list):
            return [str(item) for item in current if item]
        elif current:
            return [str(current)]
        return []

    def _auto_extract_ips(self, data: Any, results: list[str] | None = None) -> list[str]:
        """Auto-extract IP-like values from JSON.

        Args:
            data: Parsed JSON data.
            results: Accumulator for results.

        Returns:
            List of IP-like strings found.
        """
        if results is None:
            results = []

        if isinstance(data, dict):
            for key, value in data.items():
                # Check if key suggests IP content
                if any(hint in key.lower() for hint in ["ip", "cidr", "prefix", "range"]):
                    if isinstance(value, str) and self.validate_ip(value):
                        results.append(value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, str) and self.validate_ip(item):
                                results.append(item)
                else:
                    self._auto_extract_ips(value, results)
        elif isinstance(data, list):
            for item in data:
                self._auto_extract_ips(item, results)

        return results


class GitHubIPFetcher(IPFetcher):
    """Fetcher for GitHub Meta API IP ranges."""

    def __init__(self, timeout: float = 30.0) -> None:
        """Initialize the GitHub fetcher.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        self.timeout = timeout

    def fetch(self, config: IPSourceConfig) -> list[str]:
        """Fetch GitHub IP ranges.

        Args:
            config: Source configuration with optional service filters.

        Returns:
            List of GitHub IP ranges.

        Available services: hooks, web, api, git, github_enterprise_importer,
        packages, pages, importer, actions, actions_macos, dependabot, copilot
        """
        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(GITHUB_META_URL)
            response.raise_for_status()

        data = response.json()
        ips: list[str] = []

        # GitHub services that contain IP ranges
        services = config.services if config.services else [
            "hooks", "web", "api", "git", "actions", "dependabot"
        ]

        for service in services:
            if service in data:
                service_ips = data[service]
                if isinstance(service_ips, list):
                    for ip in service_ips:
                        if self.validate_ip(ip):
                            ips.append(ip)

        # Deduplicate
        ips = list(set(ips))
        logger.info("Fetched %d IPs from GitHub (%s)", len(ips), ", ".join(services))

        return self.filter_by_version(ips, config.ip_version)


class GoogleCloudIPFetcher(IPFetcher):
    """Fetcher for Google Cloud IP ranges."""

    def __init__(self, timeout: float = 30.0) -> None:
        """Initialize the Google Cloud fetcher.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        self.timeout = timeout

    def fetch(self, config: IPSourceConfig) -> list[str]:
        """Fetch Google Cloud IP ranges.

        Args:
            config: Source configuration with optional region/service filters.

        Returns:
            List of Google Cloud IP ranges.
        """
        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(GOOGLE_CLOUD_URL)
            response.raise_for_status()

        data = response.json()
        ips: list[str] = []

        for prefix in data.get("prefixes", []):
            # Check region filter
            if config.regions:
                scope = prefix.get("scope", "")
                if not any(region in scope for region in config.regions):
                    continue

            # Check service filter
            if config.services:
                service = prefix.get("service", "")
                if service not in config.services:
                    continue

            # Extract IP prefix
            ipv4 = prefix.get("ipv4Prefix")
            ipv6 = prefix.get("ipv6Prefix")

            if ipv4 and self.validate_ip(ipv4):
                ips.append(ipv4)
            if ipv6 and self.validate_ip(ipv6):
                ips.append(ipv6)

        ips = list(set(ips))
        logger.info("Fetched %d IPs from Google Cloud", len(ips))

        return self.filter_by_version(ips, config.ip_version)


class AWSIPFetcher(IPFetcher):
    """Fetcher for AWS IP ranges."""

    def __init__(self, timeout: float = 30.0) -> None:
        """Initialize the AWS fetcher.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        self.timeout = timeout

    def fetch(self, config: IPSourceConfig) -> list[str]:
        """Fetch AWS IP ranges.

        Args:
            config: Source configuration with optional region/service filters.

        Returns:
            List of AWS IP ranges.

        Available services: AMAZON, EC2, S3, CLOUDFRONT, ROUTE53,
        ROUTE53_HEALTHCHECKS, API_GATEWAY, etc.
        """
        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(AWS_IP_RANGES_URL)
            response.raise_for_status()

        data = response.json()
        ips: list[str] = []

        # Process IPv4 prefixes
        for prefix in data.get("prefixes", []):
            if not self._matches_filters(prefix, config):
                continue

            ip = prefix.get("ip_prefix")
            if ip and self.validate_ip(ip):
                ips.append(ip)

        # Process IPv6 prefixes
        for prefix in data.get("ipv6_prefixes", []):
            if not self._matches_filters(prefix, config):
                continue

            ip = prefix.get("ipv6_prefix")
            if ip and self.validate_ip(ip):
                ips.append(ip)

        ips = list(set(ips))
        logger.info("Fetched %d IPs from AWS", len(ips))

        return self.filter_by_version(ips, config.ip_version)

    def _matches_filters(self, prefix: dict[str, Any], config: IPSourceConfig) -> bool:
        """Check if a prefix matches the configured filters.

        Args:
            prefix: AWS prefix object.
            config: Source configuration.

        Returns:
            True if prefix matches filters.
        """
        # Check region filter
        if config.regions:
            region = prefix.get("region", "")
            if not any(r in region for r in config.regions):
                return False

        # Check service filter
        if config.services:
            service = prefix.get("service", "")
            if service not in config.services:
                return False

        return True


class CloudflareIPFetcher(IPFetcher):
    """Fetcher for Cloudflare's own IP ranges."""

    def __init__(self, timeout: float = 30.0) -> None:
        """Initialize the Cloudflare fetcher.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        self.timeout = timeout

    def fetch(self, config: IPSourceConfig) -> list[str]:
        """Fetch Cloudflare IP ranges.

        Args:
            config: Source configuration.

        Returns:
            List of Cloudflare IP ranges.
        """
        ips: list[str] = []

        with httpx.Client(timeout=self.timeout) as client:
            # Fetch based on IP version filter
            if config.ip_version is None or config.ip_version == 4:
                response = client.get(CLOUDFLARE_IPV4_URL)
                response.raise_for_status()
                for line in response.text.strip().split("\n"):
                    if self.validate_ip(line.strip()):
                        ips.append(line.strip())

            if config.ip_version is None or config.ip_version == 6:
                response = client.get(CLOUDFLARE_IPV6_URL)
                response.raise_for_status()
                for line in response.text.strip().split("\n"):
                    if self.validate_ip(line.strip()):
                        ips.append(line.strip())

        logger.info("Fetched %d IPs from Cloudflare", len(ips))
        return ips


def get_fetcher(source_type: SourceType) -> IPFetcher:
    """Get the appropriate fetcher for a source type.

    Args:
        source_type: Type of IP source.

    Returns:
        Appropriate fetcher instance.

    Raises:
        ValueError: If source type is not supported.
    """
    fetchers: dict[SourceType, type[IPFetcher]] = {
        SourceType.STATIC: StaticIPFetcher,
        SourceType.URL: URLIPFetcher,
        SourceType.GITHUB: GitHubIPFetcher,
        SourceType.GOOGLE_CLOUD: GoogleCloudIPFetcher,
        SourceType.AWS: AWSIPFetcher,
        SourceType.CLOUDFLARE: CloudflareIPFetcher,
    }

    fetcher_class = fetchers.get(source_type)
    if fetcher_class is None:
        msg = f"Unsupported source type: {source_type}"
        raise ValueError(msg)

    return fetcher_class()
