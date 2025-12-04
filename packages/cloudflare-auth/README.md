# byronwilliamscpa-cloudflare-auth

JWT validation and Cloudflare Access integration middleware for FastAPI/Starlette applications.

## Features

- JWT token validation with Cloudflare Access
- CSRF protection middleware
- Rate limiting
- Session management (in-memory and Redis-backed)
- Security helpers and validators
- Endpoint whitelist management

## Installation

```bash
# Basic installation
pip install "git+ssh://git@github.com/ByronWilliamsCPA/python-libs.git#subdirectory=packages/cloudflare-auth"

# With Redis support
pip install "git+ssh://git@github.com/ByronWilliamsCPA/python-libs.git#subdirectory=packages/cloudflare-auth[redis]"

# With FastAPI support
pip install "git+ssh://git@github.com/ByronWilliamsCPA/python-libs.git#subdirectory=packages/cloudflare-auth[fastapi]"

# All optional dependencies
pip install "git+ssh://git@github.com/ByronWilliamsCPA/python-libs.git#subdirectory=packages/cloudflare-auth[all]"
```

## Quick Start

```python
from fastapi import FastAPI
from cloudflare_auth import CloudflareAccessMiddleware

app = FastAPI()

# Add Cloudflare Access middleware
app.add_middleware(
    CloudflareAccessMiddleware,
    team_domain="your-team.cloudflareaccess.com",
    audience="your-application-audience-tag",
)

@app.get("/protected")
async def protected_route():
    return {"message": "You are authenticated!"}
```

## Components

- **middleware.py** - Core JWT validation middleware
- **middleware_enhanced.py** - Enhanced middleware with caching
- **csrf.py** - CSRF protection
- **models.py** - Pydantic models for JWT claims
- **rate_limiter.py** - Rate limiting implementation
- **redis_sessions.py** - Redis-backed session management
- **sessions.py** - In-memory session management
- **security_helpers.py** - Security utility functions
- **validators.py** - Input validation utilities
- **whitelist.py** - Endpoint whitelist management

## License

MIT License - see LICENSE file for details.
