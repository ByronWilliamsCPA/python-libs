# byronwilliamscpa-gcs-utilities

Google Cloud Storage utilities and helpers for Python applications.

## Features

- Simplified GCS client wrapper
- Upload, download, and manage blobs
- Bucket operations
- Custom exception handling
- Full type hints (PEP 561 compliant)

## Installation

```bash
# Basic installation
pip install "git+ssh://git@github.com/ByronWilliamsCPA/python-libs.git#subdirectory=packages/gcs-utilities"

# With async support
pip install "git+ssh://git@github.com/ByronWilliamsCPA/python-libs.git#subdirectory=packages/gcs-utilities[async]"
```

## Quick Start

```python
from gcs_utilities import GCSClient

# Initialize client
client = GCSClient(bucket_name="my-bucket")

# Upload a file
client.upload_file("local/path/file.txt", "remote/path/file.txt")

# Download a file
client.download_file("remote/path/file.txt", "local/path/file.txt")

# List blobs
blobs = client.list_blobs(prefix="remote/path/")
```

## Components

- **client.py** - GCS client wrapper with common operations
- **exceptions.py** - Custom exception classes

## Authentication

This library uses Google Cloud's default authentication. Set up authentication using one of:

1. **Service Account Key**: Set `GOOGLE_APPLICATION_CREDENTIALS` environment variable
2. **Application Default Credentials**: Run `gcloud auth application-default login`
3. **Compute Engine**: Automatic when running on GCP

## License

MIT License - see LICENSE file for details.
