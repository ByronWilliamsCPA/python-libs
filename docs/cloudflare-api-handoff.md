# Cloudflare API Package - Handoff Document

**Date**: 2025-12-04
**Repository**: python-libs (ByronWilliamsCPA/python-libs)
**Branch**: `feat/assured-oss-artifact-registry`
**Target Repository**: homelab-infra
**Package Version**: 0.1.0

---

## Executive Summary

This document describes the `cloudflare-api` package built for managing Cloudflare IP lists and automating IP range group synchronization. The package was developed in the wrong repository (`python-libs`) but is ready for migration to `homelab-infra`.

### What Was Built

1. **Cloudflare API Client** - Python SDK wrapper for managing IP lists, firewall rules, and Access policies
2. **IP Range Groups System** - Configuration-driven system to sync IP ranges from multiple sources (GitHub, GCP, AWS, static IPs) to Cloudflare lists
3. **CLI Tool** - Command-line interface for syncing IP groups
4. **Comprehensive Tests** - 83 tests covering all functionality

---

## Package Structure

```
packages/cloudflare-api/
├── src/cloudflare_api/
│   ├── __init__.py              # Main package exports
│   ├── client.py                # CloudflareAPIClient (IP list CRUD)
│   ├── exceptions.py            # Custom exception hierarchy
│   ├── models.py                # Pydantic models (IPList, IPListItem, etc.)
│   ├── settings.py              # CloudflareAPISettings (env config)
│   └── ip_groups/               # IP Range Groups System
│       ├── __init__.py          # IP groups exports
│       ├── config.py            # Configuration models (YAML schema)
│       ├── fetchers.py          # IP source fetchers (GitHub, GCP, AWS, URL, static)
│       ├── manager.py           # IPGroupManager (orchestration)
│       └── cli.py               # CLI commands
├── tests/
│   ├── test_client.py           # Client tests (26 tests)
│   ├── test_models.py           # Model tests (13 tests)
│   ├── test_settings.py         # Settings tests (12 tests)
│   └── test_ip_groups.py        # IP groups tests (32 tests)
├── pyproject.toml               # Package configuration
└── README.md                    # Package documentation
```

---

## Core Components

### 1. Cloudflare API Client ([client.py](file:///home/byron/python-libs/packages/cloudflare-api/src/cloudflare_api/client.py))

**Purpose**: High-level wrapper for Cloudflare's official Python SDK

**Key Methods**:
- `list_ip_lists()` - List all IP lists
- `get_ip_list(list_id)` - Get list details
- `get_ip_list_by_name(name)` - Find list by name
- `create_ip_list(name, kind, description)` - Create new list
- `update_ip_list(list_id, description)` - Update list
- `delete_ip_list(list_id)` - Delete list
- `get_ip_list_items(list_id)` - Get items in list
- `add_ip_list_items(list_id, items)` - Add IPs (async)
- `replace_ip_list_items(list_id, items)` - Replace all IPs (async)
- `delete_ip_list_items(list_id, item_ids)` - Delete IPs (async)
- `ensure_ip_list(name, kind, description)` - Get or create list
- `sync_ip_list(list_id, ips, comments)` - Sync list to exact IPs

**Authentication**: Uses `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` from environment

**Error Handling**: Converts Cloudflare SDK exceptions to custom exceptions:
- `CloudflareAuthError` - 401 authentication failures
- `CloudflareRateLimitError` - Rate limit exceeded
- `CloudflareNotFoundError` - 404 not found
- `CloudflareValidationError` - 400 bad request
- `CloudflareConflictError` - 409 conflicts (name exists, list in use)
- `CloudflareBulkOperationError` - Bulk operation failures
- `CloudflareAPIError` - General API errors

**File Location**: `packages/cloudflare-api/src/cloudflare_api/client.py` (692 lines)

---

### 2. IP Range Groups System

#### Configuration Schema ([config.py](file:///home/byron/python-libs/packages/cloudflare-api/src/cloudflare_api/ip_groups/config.py))

**Purpose**: Define IP groups and their sources in YAML

**Models**:
- `SourceType` - Enum: `static`, `url`, `github`, `google_cloud`, `aws`, `azure`, `cloudflare`
- `IPSourceConfig` - Configuration for a single IP source
- `IPGroupConfig` - Configuration for an IP group (maps to a Cloudflare list)
- `IPGroupsConfig` - Root configuration with all groups

**Example Config** ([ip_groups.example.yaml](file:///home/byron/python-libs/ip_groups.example.yaml)):
```yaml
version: "1.0"
cache_ttl_seconds: 3600
cloudflare_list_prefix: ""

groups:
  - name: github
    cloudflare_list_name: github-ips
    description: "GitHub Actions and webhook IPs"
    enabled: true
    sources:
      - type: github
        services: [actions, hooks, dependabot]

  - name: home-network
    cloudflare_list_name: home-ips
    description: "Home and office IPs"
    enabled: true
    sources:
      - type: static
        ips: ["203.0.113.50", "198.51.100.0/24"]
```

**File Location**: `packages/cloudflare-api/src/cloudflare_api/ip_groups/config.py` (132 lines)

---

#### IP Fetchers ([fetchers.py](file:///home/byron/python-libs/packages/cloudflare-api/src/cloudflare_api/ip_groups/fetchers.py))

**Purpose**: Fetch IP ranges from various sources

**Fetcher Classes**:

| Fetcher | Source | Filters | Notes |
|---------|--------|---------|-------|
| `StaticIPFetcher` | Hardcoded IPs in config | IP version | For home/office networks |
| `URLIPFetcher` | Generic URL (text or JSON) | IP version, JSONPath | For custom endpoints |
| `GitHubIPFetcher` | `https://api.github.com/meta` | Services (actions, hooks, etc.), IP version | GitHub Actions, webhooks |
| `GoogleCloudIPFetcher` | `https://www.gstatic.com/ipranges/cloud.json` | Regions, services, IP version | GCP IP ranges |
| `AWSIPFetcher` | `https://ip-ranges.amazonaws.com/ip-ranges.json` | Regions, services, IP version | AWS IP ranges |
| `CloudflareIPFetcher` | `https://www.cloudflare.com/ips-v4/6` | IP version | Cloudflare's own IPs |

**Key Features**:
- IP validation (IPv4/IPv6)
- Version filtering (IPv4 only, IPv6 only, or both)
- Region filtering (GCP, AWS)
- Service filtering (GitHub: actions/hooks, AWS: EC2/S3, etc.)
- JSONPath extraction for custom JSON APIs
- Auto-detection of IP fields in JSON responses

**File Location**: `packages/cloudflare-api/src/cloudflare_api/ip_groups/fetchers.py` (518 lines)

---

#### IP Group Manager ([manager.py](file:///home/byron/python-libs/packages/cloudflare-api/src/cloudflare_api/ip_groups/manager.py))

**Purpose**: Orchestrate fetching and syncing IP groups to Cloudflare

**Key Methods**:
- `from_config(path)` - Load manager from YAML config
- `fetch_source_ips(source)` - Fetch IPs from single source (with caching)
- `fetch_group_ips(group)` - Fetch all IPs for a group (all sources)
- `preview_group(name)` - Preview changes without applying
- `sync_group(name, dry_run)` - Sync a single group to Cloudflare
- `sync_all(dry_run)` - Sync all enabled groups
- `list_groups()` - List configured groups
- `clear_cache()` - Clear cached IP data

**Caching**:
- Caches fetched IPs per source (default: 1 hour TTL)
- Cache key = hash of source config
- Invalidates on config change or TTL expiration

**Sync Algorithm**:
1. Fetch IPs from all sources for the group
2. Deduplicate IPs
3. Ensure Cloudflare list exists (create if missing)
4. Get current IPs from Cloudflare
5. Calculate diff (added, removed, unchanged)
6. Replace all items in Cloudflare list if changed
7. Return `SyncResult` with stats

**File Location**: `packages/cloudflare-api/src/cloudflare_api/ip_groups/manager.py` (443 lines)

---

#### CLI Tool ([cli.py](file:///home/byron/python-libs/packages/cloudflare-api/src/cloudflare_api/ip_groups/cli.py))

**Purpose**: Command-line interface for managing IP groups

**Commands**:

```bash
# List configured groups
cloudflare-ip-groups list [--json]

# Preview changes for a group
cloudflare-ip-groups preview <group-name> [--json]

# Sync groups to Cloudflare
cloudflare-ip-groups sync [--group <name>] [--dry-run]

# Fetch IPs for a group (without syncing)
cloudflare-ip-groups fetch <group-name> [--json] [--no-cache]
```

**Configuration**:
- Default config path: `ip_groups.yaml`
- Override with: `-c/--config <path>`
- Verbose logging: `-v/--verbose`

**Entry Point**: Registered as console script in `pyproject.toml`:
```toml
[project.scripts]
cloudflare-ip-groups = "cloudflare_api.ip_groups.cli:main"
```

**File Location**: `packages/cloudflare-api/src/cloudflare_api/ip_groups/cli.py` (254 lines)

---

## Dependencies

### Runtime Dependencies
```toml
dependencies = [
    "cloudflare>=4.0.0",      # Official Cloudflare SDK
    "pydantic>=2.0.0",        # Data validation
    "pydantic-settings>=2.0.0", # Settings management
    "httpx>=0.25.0",          # HTTP client for fetchers
    "pyyaml>=6.0.0",          # YAML config parsing
]
```

### Development Dependencies
```toml
dev = [
    "pytest>=7.4.0",
    "pytest-cov>=4.1.0",
    "pytest-asyncio>=0.21.0",
    "respx>=0.21.0",          # HTTP mocking for tests
]
```

---

## Environment Variables

```bash
# Required
CLOUDFLARE_API_TOKEN=your-api-token-here
CLOUDFLARE_ACCOUNT_ID=your-account-id-here

# Optional
CLOUDFLARE_ZONE_ID=your-zone-id        # For zone-level operations
CLOUDFLARE_API_EMAIL=email@example.com # Legacy auth (not recommended)
CLOUDFLARE_API_KEY=legacy-key          # Legacy auth (not recommended)

# Optional: Timeouts
CLOUDFLARE_BULK_OPERATION_TIMEOUT=300  # Seconds (default: 300)
CLOUDFLARE_BULK_OPERATION_POLL_INTERVAL=2  # Seconds (default: 2)
```

---

## Test Coverage

**Total**: 83 tests, all passing

### Test Breakdown

1. **Client Tests** ([test_client.py](file:///home/byron/python-libs/packages/cloudflare-api/tests/test_client.py)) - 26 tests
   - IP list CRUD operations
   - Item operations (add, replace, delete)
   - Bulk operation handling
   - Error handling

2. **Model Tests** ([test_models.py](file:///home/byron/python-libs/packages/cloudflare-api/tests/test_models.py)) - 13 tests
   - IPList, IPListItem, BulkOperation models
   - Enum validation (ListKind, BulkOperationStatus)
   - API dict conversion

3. **Settings Tests** ([test_settings.py](file:///home/byron/python-libs/packages/cloudflare-api/tests/test_settings.py)) - 12 tests
   - Environment variable loading
   - Singleton pattern
   - Validation

4. **IP Groups Tests** ([test_ip_groups.py](file:///home/byron/python-libs/packages/cloudflare-api/tests/test_ip_groups.py)) - 32 tests
   - Configuration loading
   - All fetchers (static, URL, GitHub, GCP, AWS)
   - IP validation
   - Manager operations
   - Caching

**Run Tests**:
```bash
uv run pytest packages/cloudflare-api/tests/ -v
```

---

## Usage Examples

### Basic API Client

```python
from cloudflare_api import CloudflareAPIClient

client = CloudflareAPIClient()

# Create an IP list
ip_list = client.create_ip_list(
    name="blocked-ips",
    kind="ip",
    description="Blocked IP addresses"
)

# Add IPs
client.add_ip_list_items(ip_list.id, [
    {"ip": "1.2.3.4", "comment": "Spam bot"},
    {"ip": "5.6.7.8/24", "comment": "Bad network"},
])

# Get all items
items = client.get_ip_list_items(ip_list.id)

# Sync to exact set of IPs
client.sync_ip_list(ip_list.id, ["10.0.0.1", "10.0.0.2"])
```

### IP Groups Configuration

```python
from cloudflare_api.ip_groups import IPGroupManager

# Load from config file
manager = IPGroupManager.from_config("ip_groups.yaml")

# List all groups
groups = manager.list_groups()
for group in groups:
    print(f"{group['name']}: {group['enabled']}")

# Preview changes
preview = manager.preview_group("github")
print(f"Will add: {len(preview['to_add'])} IPs")
print(f"Will remove: {len(preview['to_remove'])} IPs")

# Sync all groups
results = manager.sync_all()
for result in results:
    if result.error:
        print(f"❌ {result.group_name}: {result.error}")
    else:
        print(f"✓ {result.group_name}: {result.ips_count} IPs")
```

### CLI Usage

```bash
# Create config file
cp ip_groups.example.yaml ip_groups.yaml
# Edit ip_groups.yaml with your IP groups

# Set environment variables
export CLOUDFLARE_API_TOKEN=your-token
export CLOUDFLARE_ACCOUNT_ID=your-account-id

# Preview changes
cloudflare-ip-groups preview github

# Sync all groups
cloudflare-ip-groups sync

# Dry run (preview without applying)
cloudflare-ip-groups sync --dry-run
```

---

## Automation Setup (Cron Job)

### Example Crontab Entry

```bash
# Sync IP groups every hour
0 * * * * cd /path/to/homelab-infra && /usr/bin/cloudflare-ip-groups sync >> /var/log/cloudflare-sync.log 2>&1

# Sync every 6 hours
0 */6 * * * cd /path/to/homelab-infra && /usr/bin/cloudflare-ip-groups sync

# Daily sync with notifications
0 2 * * * cd /path/to/homelab-infra && /usr/bin/cloudflare-ip-groups sync || echo "Cloudflare sync failed" | mail -s "IP Groups Sync Failed" admin@example.com
```

### Systemd Timer (Alternative)

**Service**: `/etc/systemd/system/cloudflare-sync.service`
```ini
[Unit]
Description=Sync Cloudflare IP Groups
After=network.target

[Service]
Type=oneshot
User=homelab
WorkingDirectory=/path/to/homelab-infra
Environment="CLOUDFLARE_API_TOKEN=your-token"
Environment="CLOUDFLARE_ACCOUNT_ID=your-account-id"
ExecStart=/usr/bin/cloudflare-ip-groups sync
```

**Timer**: `/etc/systemd/system/cloudflare-sync.timer`
```ini
[Unit]
Description=Sync Cloudflare IP Groups Hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

**Enable**:
```bash
sudo systemctl enable cloudflare-sync.timer
sudo systemctl start cloudflare-sync.timer
```

---

## Migration Steps to homelab-infra

### 1. Copy Package Files

```bash
# In homelab-infra repository
mkdir -p packages/cloudflare-api
cp -r /home/byron/python-libs/packages/cloudflare-api/* packages/cloudflare-api/
```

### 2. Copy Example Configuration

```bash
cp /home/byron/python-libs/ip_groups.example.yaml ip_groups.example.yaml
```

### 3. Update pyproject.toml (Root)

Add to workspace members:
```toml
[tool.uv.workspace]
members = [
    "packages/cloudflare-api",
    # ... other packages
]

[tool.uv.sources]
byronwilliamscpa-cloudflare-api = { workspace = true }
```

### 4. Install Package

```bash
# In homelab-infra
uv sync --all-extras
```

### 5. Configure Environment

```bash
# Create .env file in homelab-infra
cat >> .env <<EOF
CLOUDFLARE_API_TOKEN=your-api-token-here
CLOUDFLARE_ACCOUNT_ID=your-account-id-here
EOF
```

### 6. Create IP Groups Configuration

```bash
# Copy example and customize
cp ip_groups.example.yaml ip_groups.yaml

# Edit ip_groups.yaml:
# - Update home-network with your actual IPs
# - Enable/disable groups as needed
# - Configure which services/regions to include
```

### 7. Test Installation

```bash
# List groups
cloudflare-ip-groups list

# Preview (dry run)
cloudflare-ip-groups sync --dry-run

# Sync
cloudflare-ip-groups sync
```

---

## File Locations (python-libs repo)

All files are in branch: `feat/assured-oss-artifact-registry`

### Core Package Files
```
packages/cloudflare-api/
├── src/cloudflare_api/
│   ├── __init__.py                           # Line count: 66
│   ├── client.py                             # Line count: 692
│   ├── exceptions.py                         # Line count: 138
│   ├── models.py                             # Line count: 136
│   ├── settings.py                           # Line count: 136
│   └── ip_groups/
│       ├── __init__.py                       # Line count: 46
│       ├── config.py                         # Line count: 132
│       ├── fetchers.py                       # Line count: 518
│       ├── manager.py                        # Line count: 443
│       └── cli.py                            # Line count: 254
├── tests/
│   ├── conftest.py                           # Line count: 62
│   ├── test_client.py                        # Line count: 626
│   ├── test_models.py                        # Line count: 208
│   ├── test_settings.py                      # Line count: 162
│   └── test_ip_groups.py                     # Line count: 522
├── pyproject.toml                            # Line count: 67
└── README.md                                 # Line count: 325
```

### Configuration Examples
```
ip_groups.example.yaml                        # Line count: 176
```

### Documentation
```
docs/cloudflare-api-handoff.md               # This file
```

**Total Lines of Code**: ~4,709 lines

---

## Key Design Decisions

### 1. Official Cloudflare SDK
- Uses `cloudflare>=4.0.0` SDK instead of raw API calls
- Handles authentication, rate limiting, retries automatically
- Type-safe with SDK models

### 2. Configuration-Driven
- YAML configuration for IP groups (not hardcoded)
- Easy to add/remove groups and sources
- Version controlled alongside infrastructure

### 3. Source Abstraction
- Fetcher pattern for pluggable IP sources
- Easy to add new sources (Azure, custom APIs)
- Consistent interface for all sources

### 4. Caching Strategy
- Caches fetched IPs to reduce API calls
- Invalidates on config change or TTL expiration
- Respects rate limits of external APIs

### 5. Error Handling
- Custom exception hierarchy
- Converts SDK exceptions to domain exceptions
- Provides context in error messages

### 6. Idempotent Syncing
- `sync_ip_list()` replaces all items atomically
- Handles concurrent bulk operations
- Returns detailed diff (added, removed, unchanged)

### 7. Testing Strategy
- Mocked HTTP responses (no live API calls)
- Tests all fetchers with realistic data
- Tests error conditions and edge cases

---

## Known Limitations

1. **Azure Support**: Azure fetcher defined but not tested (Azure IP ranges URL is a download link, not direct JSON)
2. **Bulk Operations**: Cloudflare API has pending operation limits (handled with error)
3. **Large Lists**: Very large IP lists (>10,000 items) may hit API limits
4. **JSONPath**: Simple JSONPath implementation (supports `key[*].field`, not complex expressions)
5. **Rate Limiting**: No retry logic for rate limits (SDK handles it, but could be enhanced)

---

## Recommended Next Steps

### For homelab-infra Integration

1. **Migrate Package** (see Migration Steps above)
2. **Configure IP Groups** for homelab environment:
   - Home/office network IPs
   - GitHub Actions for CI/CD
   - Cloud provider IPs (GCP, AWS)
3. **Setup Cron Job** for hourly syncing
4. **Create Cloudflare Access Policies** that reference the synced IP lists
5. **Monitor Sync Logs** for failures

### Potential Enhancements

1. **GitHub Action Workflow** - Automate syncing on schedule or PR merge
2. **Alerting** - Notify on sync failures (email, Slack, PagerDuty)
3. **Metrics** - Track sync duration, IP count changes over time
4. **Webhooks** - Trigger sync when infrastructure changes
5. **Backup/Restore** - Export current Cloudflare lists before sync
6. **Diff Reports** - Email detailed diff of IP changes
7. **Azure Support** - Implement full Azure IP fetcher
8. **Web UI** - Dashboard for viewing groups, previewing changes

---

## Support & Questions

**Original Implementation**: Built by Claude Code in `python-libs` repository
**Branch**: `feat/assured-oss-artifact-registry`
**Tests**: 83 tests, all passing
**Documentation**: README.md in package directory

**Contact**: Byron Williams <byronawilliams@gmail.com>

---

## Appendix: Example IP Groups Configuration

See [ip_groups.example.yaml](file:///home/byron/python-libs/ip_groups.example.yaml) for complete example.

**Minimal Configuration**:
```yaml
version: "1.0"
cache_ttl_seconds: 3600

groups:
  - name: home-network
    cloudflare_list_name: home-ips
    enabled: true
    sources:
      - type: static
        ips:
          - "203.0.113.50"        # Your home IP
          - "198.51.100.0/24"     # Your office network

  - name: github-actions
    cloudflare_list_name: github-ips
    enabled: true
    sources:
      - type: github
        services: [actions]
        ip_version: 4
```

**Advanced Configuration** (Multi-Source Group):
```yaml
  - name: ci-cd
    cloudflare_list_name: ci-cd-ips
    description: "All CI/CD service IPs"
    enabled: true
    sources:
      # GitHub Actions
      - type: github
        services: [actions]

      # Google Cloud Build regions
      - type: google_cloud
        regions: [us-central1, us-east1]
        ip_version: 4

      # Custom CI service
      - type: url
        url: "https://ci.example.com/ips.txt"
```

---

**END OF HANDOFF DOCUMENT**
