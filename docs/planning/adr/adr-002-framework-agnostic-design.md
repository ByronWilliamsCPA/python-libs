---
title: "ADR-002: Framework-Agnostic Core with Optional Adapters"
schema_type: planning
status: accepted
owner: core-maintainer
purpose: "Document the decision to separate framework-agnostic core from framework-specific adapters."
tags:
  - planning
  - architecture
  - decisions
---

## ADR-002: Framework-Agnostic Core with Optional Adapters

> **Status**: Accepted
> **Date**: 2025-12-04

### TL;DR

Structure packages with framework-agnostic core logic and optional framework-specific adapters (e.g., FastAPI), enabling reuse across different contexts while providing convenient integrations.

### Context

#### Problem

The `cloudflare-auth` package currently requires FastAPI/Starlette as dependencies. This tight coupling prevents use in:

- CLI tools that validate tokens offline
- Background workers processing authenticated requests
- Future projects using different frameworks (Flask, Litestar)
- Non-web contexts needing auth logic

#### Constraints

- **Technical**: Cannot break existing FastAPI integrations
- **Business**: Limited time for major refactoring; must be incremental

#### Significance

Coupling to FastAPI limits reusability. If we add Flask support later, we'd either duplicate core logic or force a breaking refactor. Better to establish the pattern now.

### Decision

**We will separate framework-agnostic core from framework adapters because it maximizes reusability without sacrificing convenience.**

#### Rationale

- Core logic (JWT validation, user models, token parsing) has no framework dependency
- Framework-specific code (middleware, request/response handling) is isolated
- Optional dependencies allow consumers to install only what they need
- Pattern is widely used (e.g., SQLAlchemy core vs ORM, Pydantic vs FastAPI)

### Options Considered

#### Option 1: Framework-Agnostic Core + Optional Adapters ✓

**Pros**:
- ✅ Core logic usable anywhere (CLI, workers, any framework)
- ✅ Optional dependencies keep install size small
- ✅ Easy to add new framework support
- ✅ Better testability (core logic tested without mocking framework)

**Cons**:
- ❌ Slightly more complex package structure
- ❌ Refactoring effort for existing code

#### Option 2: Maintain FastAPI Coupling

**Pros**:
- ✅ No refactoring needed
- ✅ Simpler package structure

**Cons**:
- ❌ Cannot use in non-FastAPI contexts
- ❌ Forces FastAPI dependency on all consumers
- ❌ Harder to test core logic in isolation

#### Option 3: Separate Packages per Framework

**Pros**:
- ✅ Complete isolation

**Cons**:
- ❌ Duplicated core logic or complex dependency chain
- ❌ Multiple packages to version and maintain
- ❌ Overkill for current needs

### Consequences

#### Positive

- ✅ **Broader applicability**: Auth logic usable in CLI tools, workers, any framework
- ✅ **Better testing**: Core logic tested without framework mocks
- ✅ **Future-proof**: Easy to add Flask, Litestar adapters if needed

#### Trade-offs

- ⚠️ **Refactoring required**: `cloudflare-auth` needs restructuring
- ⚠️ **Learning curve**: Developers must understand core vs adapter distinction

#### Technical Debt

- Current `cloudflare-auth` middleware.py mixes core and FastAPI code; needs refactoring

### Implementation

#### Components Affected

1. **cloudflare-auth/core/**: Framework-agnostic JWT validation, models
2. **cloudflare-auth/fastapi/**: Middleware, dependencies, request handling
3. **pyproject.toml**: Optional dependencies for framework extras

#### Target Structure

```
cloudflare-auth/
├── src/cloudflare_auth/
│   ├── __init__.py           # Public API
│   ├── core/                  # Framework-agnostic
│   │   ├── __init__.py
│   │   ├── models.py         # CloudflareUser, CloudflareJWTClaims
│   │   ├── validators.py     # JWT validation logic
│   │   └── exceptions.py     # Auth exceptions
│   └── fastapi/              # FastAPI-specific
│       ├── __init__.py
│       ├── middleware.py     # CloudflareAuthMiddleware
│       └── dependencies.py   # get_current_user, require_admin
└── pyproject.toml
```

#### Optional Dependencies

```toml
[project.optional-dependencies]
fastapi = ["fastapi>=0.100.0", "starlette>=0.27.0"]
redis = ["redis>=4.0.0"]
all = ["fastapi>=0.100.0", "starlette>=0.27.0", "redis>=4.0.0"]
```

#### Usage Examples

```python
# Core only (CLI, workers)
from cloudflare_auth.core import CloudflareJWTValidator, CloudflareUser
validator = CloudflareJWTValidator(team_domain="example", policy_aud="...")
claims = validator.validate_token(jwt_token)

# With FastAPI
from cloudflare_auth.fastapi import CloudflareAuthMiddleware, get_current_user
app.add_middleware(CloudflareAuthMiddleware)
```

### Validation

#### Success Criteria

- [ ] Core validation works without FastAPI installed
- [ ] FastAPI middleware works with `[fastapi]` extra
- [ ] Existing FastAPI code migrates with minimal changes
- [ ] Test coverage maintained at 80%+

#### Review Schedule

- Initial: After Phase 2 refactoring
- Ongoing: When adding new framework adapters

### Related

- [ADR-001](./adr-001-monorepo-architecture.md): Monorepo structure
- [ADR-003](./adr-003-distribution-strategy.md): Package distribution approach
- [Tech Spec](../tech-spec.md#security): Authentication details
