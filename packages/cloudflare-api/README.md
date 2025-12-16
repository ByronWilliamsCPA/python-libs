# Cloudflare API Client

A Python client for managing Cloudflare resources including IP lists, firewall rules, and Access policies.

## Installation

```bash
pip install byronwilliamscpa-cloudflare-api
```

Or install from Artifact Registry:

```bash
pip install --index-url https://us-central1-python.pkg.dev/assured-oss-457903/python-libs/simple/ byronwilliamscpa-cloudflare-api
```

## Features

- IP List management (create, update, delete lists and items)
- Async bulk operations with status tracking
- Pydantic settings for configuration
- Type-safe API with full type hints

## Configuration

Set environment variables:

```bash
export CLOUDFLARE_API_TOKEN="your-api-token"
export CLOUDFLARE_ACCOUNT_ID="your-account-id"
```

Or use a `.env` file:

```env
CLOUDFLARE_API_TOKEN=your-api-token
CLOUDFLARE_ACCOUNT_ID=your-account-id
```

## Usage

### Basic Usage

```python
from cloudflare_api import CloudflareAPIClient, get_cloudflare_api_settings

# Using environment variables
client = CloudflareAPIClient()

# List all IP lists
lists = client.list_ip_lists()
for ip_list in lists:
    print(f"{ip_list.name}: {ip_list.num_items} items")
```

### Managing IP Lists

```python
from cloudflare_api import CloudflareAPIClient

client = CloudflareAPIClient()

# Create a new IP list
new_list = client.create_ip_list(
    name="blocked-ips",
    kind="ip",
    description="IPs to block"
)

# Add IPs to the list
client.add_ip_list_items(
    list_id=new_list.id,
    items=[
        {"ip": "192.168.1.1", "comment": "Bad actor"},
        {"ip": "10.0.0.0/8", "comment": "Internal range"},
    ]
)

# Get list contents
items = client.get_ip_list_items(list_id=new_list.id)
for item in items:
    print(f"{item.ip} - {item.comment}")

# Replace all items in a list
client.replace_ip_list_items(
    list_id=new_list.id,
    items=[
        {"ip": "203.0.113.0/24", "comment": "New blocklist"},
    ]
)

# Delete specific items
client.delete_ip_list_items(
    list_id=new_list.id,
    item_ids=["item-id-1", "item-id-2"]
)

# Delete the entire list
client.delete_ip_list(list_id=new_list.id)
```

### Async Operations

IP list item operations are asynchronous. You can track operation status:

```python
# Add items and get operation ID
operation_id = client.add_ip_list_items(
    list_id="list-id",
    items=[{"ip": "1.2.3.4"}],
    return_operation_id=True
)

# Check operation status
status = client.get_bulk_operation_status(operation_id)
print(f"Status: {status.status}")  # pending, running, completed, failed
```

### Custom Settings

```python
from cloudflare_api import CloudflareAPIClient, CloudflareAPISettings

settings = CloudflareAPISettings(
    cloudflare_api_token="your-token",
    cloudflare_account_id="your-account-id",
)

client = CloudflareAPIClient(settings=settings)
```

## API Token Permissions

Your Cloudflare API token needs the following permissions:

- **Account > Account Filter Lists > Edit** - For IP list management
- **Account > Account Firewall Access Rules > Edit** - For firewall rules (if needed)
- **Account > Access: Apps and Policies > Edit** - For Access policies (if needed)

## License

MIT License - see LICENSE file for details.
