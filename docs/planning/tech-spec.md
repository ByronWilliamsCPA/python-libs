---
title: "Python Libs - Technical Specification"
schema_type: planning
status: active
owner: core-maintainer
purpose: "Document the technical architecture and implementation details."
tags:
  - planning
  - architecture
component: Development-Tools
source: "/plan command generation"
---

## Technical Implementation Spec: Python Libs

> **Status**: Active | **Version**: 1.0 | **Updated**: 2025-12-04

### TL;DR

UV workspace monorepo hosting independent Python packages for shared utilities. Each package follows framework-agnostic core design with optional adapters. Distribution via Git dependencies initially, migrating to Artifact Registry.

## Technology Stack

### Core

- **Language**: Python 3.10-3.14
- **Package Manager**: UV with workspace support
- **Build Backend**: Hatchling

### Code Quality

- **Linter/Formatter**: Ruff (88 chars, Google style)
- **Type Checker**: BasedPyright (strict mode)
- **Testing**: pytest with pytest-cov, pytest-asyncio
- **Security**: Bandit, pip-audit, Safety

### Infrastructure

- **CI/CD**: GitHub Actions
- **Documentation**: MkDocs Material
- **Version Control**: Git with conventional commits

## Architecture

### Pattern

UV Workspace Monorepo - See [ADR-001](./adr/adr-001-monorepo-architecture.md)

### Component Diagram

```text
┌─────────────────────────────────────────────────────────────────┐
│                     python-libs (workspace)                      │
├─────────────────────────────────────────────────────────────────┤
│  packages/                                                       │
│  ├── cloudflare-auth/          ├── gcs-utilities/               │
│  │   ├── core/                 │   ├── client.py                │
│  │   │   ├── models.py         │   ├── exceptions.py            │
│  │   │   ├── validators.py     │   └── __init__.py              │
│  │   │   └── exceptions.py     │                                │
│  │   └── fastapi/              └── [future packages]            │
│  │       ├── middleware.py                                       │
│  │       └── dependencies.py                                     │
├─────────────────────────────────────────────────────────────────┤
│  src/python_libs/              (shared workspace utilities)      │
│  ├── core/                                                       │
│  │   ├── config.py             # Base Pydantic Settings          │
│  │   └── exceptions.py         # Shared exception hierarchy      │
│  └── utils/                                                      │
│      ├── logging.py            # Structured logging setup        │
│      └── financial.py          # Decimal precision utilities     │
└─────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Purpose | Key Functions |
|-----------|---------|---------------|
| `gcs-utilities` | Google Cloud Storage operations | upload, download, list, delete with auth handling |
| `cloudflare-auth` | Zero Trust authentication | JWT validation, middleware, user models |
| `python_libs.core` | Shared foundations | Base config, exceptions |
| `python_libs.utils` | Cross-cutting utilities | Logging setup, financial calculations |

## Data Model

### gcs-utilities (Existing)

```python
from gcs_utilities import GCSClient

client = GCSClient()  # Reads GCP_SA_KEY from env
client.upload_file("local.txt", "remote/path.txt")
files = client.list_files(prefix="remote/")
```

**Core Entities**:

```python
class GCSClient:
    bucket_name: str | None
    project_id: str | None
    client: storage.Client

class GCSAuthError(Exception): ...
class GCSUploadError(Exception): ...
class GCSDownloadError(Exception): ...
class GCSNotFoundError(Exception): ...
```

### cloudflare-auth (Existing, Refactoring Planned)

```python
# Current (FastAPI-coupled)
from cloudflare_auth import setup_cloudflare_auth_enhanced, get_current_user

# Future (Framework-agnostic core)
from cloudflare_auth.core import CloudflareJWTValidator
from cloudflare_auth.fastapi import CloudflareAuthMiddleware
```

**Core Entities**:

```python
class CloudflareUser:
    email: str
    user_id: str
    user_tier: UserTier
    iat: datetime
    exp: datetime

class CloudflareJWTClaims:
    email: str
    sub: str
    iat: int
    exp: int
    iss: str
    aud: list[str]
```

### python_libs.core (Workspace Shared)

```python
from python_libs.core.config import BaseSettings
from python_libs.core.exceptions import ValidationError, ConfigurationError
```

### python_libs.utils (Workspace Shared)

```python
from python_libs.utils.logging import setup_logging, get_logger
from python_libs.utils.financial import round_currency, validate_amount
```

## Distribution

### Git Dependencies (Phase 1)

```toml
# Consumer pyproject.toml
[project]
dependencies = [
    "byronwilliamscpa-gcs-utilities @ git+https://github.com/ByronWilliamsCPA/python-libs.git@gcs-utilities-v0.1.0#subdirectory=packages/gcs-utilities",
]
```

### Artifact Registry (Phase 2)

See [ADR-003](./adr/adr-003-distribution-strategy.md) for migration plan.

## Security

### Authentication Handling

- **GCS**: Base64-encoded service account keys via `GCP_SA_KEY` environment variable
- **Cloudflare**: JWT validation against Cloudflare Access public keys
- **Credentials**: Never logged, temporary files cleaned up automatically

### Input Validation

- Path traversal prevention in GCS operations (`_sanitize_gcs_path`)
- JWT size limits to prevent DoS
- Email sanitization in logs

### Data Protection

- **At Rest**: Credentials in environment variables or secrets manager
- **In Transit**: All external calls over HTTPS/TLS
- **Sensitive Data**: Never log credentials, tokens, or PII

## Error Handling

### Strategy

Fail-fast with descriptive exceptions. Each package defines its own exception hierarchy inheriting from a base exception.

### Exception Hierarchy

```python
# gcs-utilities
GCSError (base)
├── GCSAuthError
├── GCSConfigError
├── GCSUploadError
├── GCSDownloadError
└── GCSNotFoundError

# cloudflare-auth
CloudflareAuthError (base)
├── TokenValidationError
├── TokenExpiredError
└── InvalidAudienceError

# python_libs.core
PythonLibsError (base)
├── ConfigurationError
├── ValidationError
└── ExternalServiceError
```

### Logging

- **Format**: Structured JSON via structlog
- **Levels**: DEBUG for operations, INFO for success, WARNING for recoverable issues, ERROR for failures
- **Sensitive**: Never log credentials, tokens, full file contents

## Performance

| Metric | Target | Measurement |
|--------|--------|-------------|
| Package install (Git) | < 30s | CI/CD timing |
| Package install (Artifact Registry) | < 10s | CI/CD timing |
| JWT validation | < 10ms | Unit test benchmark |
| GCS small file upload | < 2s | Integration test |

## Testing

### Coverage Target

- Minimum: 80%
- Critical paths (auth, credentials): 100%

### Test Types

- **Unit**: Core logic, validators, models (no external calls)
- **Integration**: GCS operations with emulator, JWT with test tokens
- **Package Tests**: Each package has own test directory

### Test Structure

```text
packages/
├── gcs-utilities/
│   └── tests/
│       ├── test_client.py
│       ├── test_exceptions.py
│       └── conftest.py
├── cloudflare-auth/
│   └── tests/
│       ├── test_validators.py
│       ├── test_models.py
│       └── conftest.py
└── tests/                    # Workspace-level tests
    ├── unit/
    └── integration/
```

## Versioning

### Semantic Versioning

Each package versioned independently following SemVer:

- **Major**: Breaking API changes
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes, backward compatible

### Git Tags

```text
gcs-utilities-v0.1.0
cloudflare-auth-v0.2.0
```

### Changelog

Each package maintains its own `CHANGELOG.md` following Keep a Changelog format.

## Related Documents

- [Project Vision](./project-vision.md)
- [Architecture Decisions](./adr/)
- [Development Roadmap](./roadmap.md)
