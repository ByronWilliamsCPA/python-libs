"""Tests for IP groups functionality."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from cloudflare_api.ip_groups.config import (
    IPGroupConfig,
    IPGroupsConfig,
    IPSourceConfig,
    SourceType,
    load_config,
)
from cloudflare_api.ip_groups.fetchers import (
    AWSIPFetcher,
    CloudflareIPFetcher,
    GitHubIPFetcher,
    GoogleCloudIPFetcher,
    IPFetcher,
    StaticIPFetcher,
    URLIPFetcher,
    get_fetcher,
)
from cloudflare_api.ip_groups.manager import IPGroupManager


class TestIPSourceConfig:
    """Tests for IP source configuration."""

    def test_static_source(self):
        """Test static IP source configuration."""
        config = IPSourceConfig(
            type=SourceType.STATIC,
            ips=["192.168.1.1", "10.0.0.0/8"],
        )
        assert config.type == SourceType.STATIC
        assert len(config.ips) == 2

    def test_github_source(self):
        """Test GitHub source configuration."""
        config = IPSourceConfig(
            type=SourceType.GITHUB,
            services=["actions", "hooks"],
        )
        assert config.type == SourceType.GITHUB
        assert "actions" in config.services

    def test_url_source(self):
        """Test URL source configuration."""
        config = IPSourceConfig(
            type=SourceType.URL,
            url="https://example.com/ips.txt",
            json_path="prefixes[*].ip",
        )
        assert config.url == "https://example.com/ips.txt"
        assert config.json_path == "prefixes[*].ip"

    def test_ip_version_validation(self):
        """Test IP version validation."""
        # Valid versions
        config = IPSourceConfig(type=SourceType.STATIC, ip_version=4)
        assert config.ip_version == 4

        config = IPSourceConfig(type=SourceType.STATIC, ip_version=6)
        assert config.ip_version == 6

        # Invalid version
        with pytest.raises(ValueError, match="ip_version must be 4 or 6"):
            IPSourceConfig(type=SourceType.STATIC, ip_version=5)


class TestIPGroupConfig:
    """Tests for IP group configuration."""

    def test_basic_group(self):
        """Test basic group configuration."""
        config = IPGroupConfig(
            name="test-group",
            cloudflare_list_name="test-list",
            description="Test group",
            sources=[
                IPSourceConfig(type=SourceType.STATIC, ips=["1.2.3.4"]),
            ],
        )
        assert config.name == "test-group"
        assert config.cloudflare_list_name == "test-list"
        assert config.enabled is True
        assert len(config.sources) == 1

    def test_disabled_group(self):
        """Test disabled group."""
        config = IPGroupConfig(
            name="disabled",
            cloudflare_list_name="disabled-list",
            enabled=False,
            sources=[],
        )
        assert config.enabled is False


class TestLoadConfig:
    """Tests for configuration loading."""

    def test_load_valid_config(self):
        """Test loading a valid configuration file."""
        config_data = {
            "version": "1.0",
            "cache_ttl_seconds": 1800,
            "groups": [
                {
                    "name": "home",
                    "cloudflare_list_name": "home-ips",
                    "sources": [
                        {"type": "static", "ips": ["192.168.1.1"]},
                    ],
                },
            ],
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(config_data, f)
            f.flush()

            config = load_config(f.name)

        assert config.version == "1.0"
        assert config.cache_ttl_seconds == 1800
        assert len(config.groups) == 1
        assert config.groups[0].name == "home"

        Path(f.name).unlink()

    def test_load_missing_file(self):
        """Test loading a missing file raises error."""
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path.yaml")


class TestStaticIPFetcher:
    """Tests for static IP fetcher."""

    def test_fetch_valid_ips(self):
        """Test fetching valid static IPs."""
        config = IPSourceConfig(
            type=SourceType.STATIC,
            ips=["192.168.1.1", "10.0.0.0/8", "2001:db8::1"],
        )
        fetcher = StaticIPFetcher()
        ips = fetcher.fetch(config)

        assert len(ips) == 3
        assert "192.168.1.1" in ips
        assert "10.0.0.0/8" in ips

    def test_fetch_filters_invalid_ips(self):
        """Test that invalid IPs are filtered out."""
        config = IPSourceConfig(
            type=SourceType.STATIC,
            ips=["192.168.1.1", "invalid-ip", "10.0.0.0/8"],
        )
        fetcher = StaticIPFetcher()
        ips = fetcher.fetch(config)

        assert len(ips) == 2
        assert "invalid-ip" not in ips

    def test_fetch_filters_by_version(self):
        """Test filtering by IP version."""
        config = IPSourceConfig(
            type=SourceType.STATIC,
            ips=["192.168.1.1", "2001:db8::1"],
            ip_version=4,
        )
        fetcher = StaticIPFetcher()
        ips = fetcher.fetch(config)

        assert len(ips) == 1
        assert "192.168.1.1" in ips


class TestIPFetcherValidation:
    """Tests for IP validation in fetchers."""

    def test_validate_ipv4(self):
        """Test IPv4 validation."""
        assert IPFetcher.validate_ip("192.168.1.1") is True
        assert IPFetcher.validate_ip("10.0.0.0/8") is True
        assert IPFetcher.validate_ip("0.0.0.0") is True
        assert IPFetcher.validate_ip("255.255.255.255") is True

    def test_validate_ipv6(self):
        """Test IPv6 validation."""
        assert IPFetcher.validate_ip("2001:db8::1") is True
        assert IPFetcher.validate_ip("::1") is True
        assert IPFetcher.validate_ip("fe80::/10") is True

    def test_validate_invalid(self):
        """Test invalid IP validation."""
        assert IPFetcher.validate_ip("invalid") is False
        assert IPFetcher.validate_ip("256.1.1.1") is False
        assert IPFetcher.validate_ip("") is False

    def test_get_ip_version(self):
        """Test IP version detection."""
        assert IPFetcher.get_ip_version("192.168.1.1") == 4
        assert IPFetcher.get_ip_version("10.0.0.0/8") == 4
        assert IPFetcher.get_ip_version("2001:db8::1") == 6
        assert IPFetcher.get_ip_version("fe80::/10") == 6


class TestURLIPFetcher:
    """Tests for URL IP fetcher."""

    def test_parse_text_response(self):
        """Test parsing plain text IP list."""
        fetcher = URLIPFetcher()
        config = IPSourceConfig(type=SourceType.URL, url="http://example.com")

        text = """
        # Comment
        192.168.1.1
        10.0.0.0/8

        2001:db8::1
        """

        ips = fetcher._parse_text(text, config)
        assert len(ips) == 3

    def test_parse_json_with_path(self):
        """Test parsing JSON with JSONPath."""
        fetcher = URLIPFetcher()
        config = IPSourceConfig(
            type=SourceType.URL,
            url="http://example.com",
            json_path="prefixes[*].cidr",
        )

        json_text = json.dumps({
            "prefixes": [
                {"cidr": "192.168.1.0/24"},
                {"cidr": "10.0.0.0/8"},
            ]
        })

        ips = fetcher._parse_json(json_text, config)
        assert len(ips) == 2


class TestGetFetcher:
    """Tests for fetcher factory."""

    def test_get_static_fetcher(self):
        """Test getting static fetcher."""
        fetcher = get_fetcher(SourceType.STATIC)
        assert isinstance(fetcher, StaticIPFetcher)

    def test_get_url_fetcher(self):
        """Test getting URL fetcher."""
        fetcher = get_fetcher(SourceType.URL)
        assert isinstance(fetcher, URLIPFetcher)

    def test_get_github_fetcher(self):
        """Test getting GitHub fetcher."""
        fetcher = get_fetcher(SourceType.GITHUB)
        assert isinstance(fetcher, GitHubIPFetcher)

    def test_get_google_cloud_fetcher(self):
        """Test getting Google Cloud fetcher."""
        fetcher = get_fetcher(SourceType.GOOGLE_CLOUD)
        assert isinstance(fetcher, GoogleCloudIPFetcher)

    def test_get_aws_fetcher(self):
        """Test getting AWS fetcher."""
        fetcher = get_fetcher(SourceType.AWS)
        assert isinstance(fetcher, AWSIPFetcher)

    def test_get_cloudflare_fetcher(self):
        """Test getting Cloudflare fetcher."""
        fetcher = get_fetcher(SourceType.CLOUDFLARE)
        assert isinstance(fetcher, CloudflareIPFetcher)


class TestIPGroupManager:
    """Tests for IP group manager."""

    @pytest.fixture
    def sample_config(self):
        """Create sample configuration."""
        return IPGroupsConfig(
            version="1.0",
            cache_ttl_seconds=3600,
            groups=[
                IPGroupConfig(
                    name="test-group",
                    cloudflare_list_name="test-list",
                    description="Test",
                    sources=[
                        IPSourceConfig(
                            type=SourceType.STATIC,
                            ips=["192.168.1.1", "10.0.0.0/8"],
                        ),
                    ],
                ),
                IPGroupConfig(
                    name="disabled-group",
                    cloudflare_list_name="disabled-list",
                    enabled=False,
                    sources=[],
                ),
            ],
        )

    @pytest.fixture
    def mock_client(self):
        """Create mock Cloudflare client."""
        client = MagicMock()
        client.get_ip_list_by_name.return_value = None
        client.ensure_ip_list.return_value = MagicMock(id="list-123")
        client.get_ip_list_items.return_value = []
        return client

    def test_list_groups(self, sample_config):
        """Test listing configured groups."""
        manager = IPGroupManager(sample_config)
        groups = manager.list_groups()

        assert len(groups) == 2
        assert groups[0]["name"] == "test-group"
        assert groups[0]["enabled"] is True
        assert groups[1]["enabled"] is False

    def test_fetch_group_ips(self, sample_config):
        """Test fetching IPs for a group."""
        manager = IPGroupManager(sample_config)
        ips = manager.fetch_group_ips(sample_config.groups[0])

        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "10.0.0.0/8" in ips

    def test_get_group_not_found(self, sample_config):
        """Test error when group not found."""
        manager = IPGroupManager(sample_config)

        with pytest.raises(ValueError, match="not found"):
            manager._get_group("nonexistent")

    def test_sync_disabled_group(self, sample_config, mock_client):
        """Test syncing a disabled group."""
        manager = IPGroupManager(sample_config, mock_client)
        result = manager.sync_group("disabled-group")

        assert result.error == "Group is disabled"
        mock_client.sync_ip_list.assert_not_called()

    def test_cache_invalidation(self, sample_config):
        """Test cache invalidation when config changes."""
        manager = IPGroupManager(sample_config)

        source = sample_config.groups[0].sources[0]
        hash1 = manager._get_source_hash(source)

        # Change config
        source.ips.append("1.2.3.4")
        hash2 = manager._get_source_hash(source)

        assert hash1 != hash2

    def test_cloudflare_list_prefix(self):
        """Test Cloudflare list name prefix."""
        config = IPGroupsConfig(
            cloudflare_list_prefix="myapp-",
            groups=[
                IPGroupConfig(
                    name="test",
                    cloudflare_list_name="ips",
                    sources=[],
                ),
            ],
        )
        manager = IPGroupManager(config)
        list_name = manager._get_cloudflare_list_name(config.groups[0])

        assert list_name == "myapp-ips"


class TestGitHubIPFetcher:
    """Tests for GitHub IP fetcher."""

    @patch("cloudflare_api.ip_groups.fetchers.httpx.Client")
    def test_fetch_github_ips(self, mock_client_class):
        """Test fetching GitHub IPs."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "hooks": ["192.168.1.1/32", "192.168.1.2/32"],
            "actions": ["10.0.0.1/24", "10.0.0.2/24"],
            "web": ["172.16.0.1/16"],
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client_class.return_value = mock_client

        config = IPSourceConfig(
            type=SourceType.GITHUB,
            services=["hooks", "actions"],
        )
        fetcher = GitHubIPFetcher()
        ips = fetcher.fetch(config)

        assert len(ips) == 4
        assert "192.168.1.1/32" in ips
        assert "10.0.0.1/24" in ips
        # web should not be included (not in services filter)
        assert "172.16.0.1/16" not in ips


class TestGoogleCloudIPFetcher:
    """Tests for Google Cloud IP fetcher."""

    @patch("cloudflare_api.ip_groups.fetchers.httpx.Client")
    def test_fetch_gcp_ips(self, mock_client_class):
        """Test fetching Google Cloud IPs."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "prefixes": [
                {"ipv4Prefix": "34.0.0.0/8", "scope": "us-central1"},
                {"ipv4Prefix": "35.0.0.0/8", "scope": "europe-west1"},
                {"ipv6Prefix": "2600:1900::/28", "scope": "us-central1"},
            ]
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client_class.return_value = mock_client

        config = IPSourceConfig(
            type=SourceType.GOOGLE_CLOUD,
            ip_version=4,
        )
        fetcher = GoogleCloudIPFetcher()
        ips = fetcher.fetch(config)

        assert len(ips) == 2
        assert "34.0.0.0/8" in ips
        assert "35.0.0.0/8" in ips
        # IPv6 should be filtered out
        assert "2600:1900::/28" not in ips

    @patch("cloudflare_api.ip_groups.fetchers.httpx.Client")
    def test_fetch_gcp_ips_with_region_filter(self, mock_client_class):
        """Test filtering Google Cloud IPs by region."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "prefixes": [
                {"ipv4Prefix": "34.0.0.0/8", "scope": "us-central1"},
                {"ipv4Prefix": "35.0.0.0/8", "scope": "europe-west1"},
            ]
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client_class.return_value = mock_client

        config = IPSourceConfig(
            type=SourceType.GOOGLE_CLOUD,
            regions=["us-central1"],
        )
        fetcher = GoogleCloudIPFetcher()
        ips = fetcher.fetch(config)

        assert len(ips) == 1
        assert "34.0.0.0/8" in ips
