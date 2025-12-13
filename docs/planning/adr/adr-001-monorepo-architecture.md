---
title: "ADR-001: UV Workspace Monorepo Architecture"
schema_type: planning
status: accepted
owner: core-maintainer
purpose: "Document the decision to use UV workspace monorepo for shared libraries."
tags:
  - planning
  - architecture
  - decisions
---

## ADR-001: UV Workspace Monorepo Architecture

> **Status**: Accepted
> **Date**: 2025-12-04

### TL;DR

Use UV workspace monorepo to manage multiple independent packages (gcs-utilities, cloudflare-auth, etc.) in a single repository, enabling coordinated development while maintaining separate versioning and publishing.

### Context

#### Problem

The organization needs to share Python utilities across multiple projects (data_ingestor, image-preprocessing-detector, ledgerbase, magg). Options for structuring shared code include:

1. Single monolithic package with all utilities
2. Separate repositories for each utility package
3. Monorepo with independent packages

#### Constraints

- **Technical**: Need independent versioning per package; some packages have different dependencies
- **Business**: Single developer maintaining multiple projects; minimize context-switching overhead

#### Significance

This decision affects how packages are developed, versioned, tested, and published. Wrong choice leads to either tight coupling (monolithic) or coordination overhead (multiple repos).

### Decision

**We will use UV workspace monorepo because it provides independent package management with unified development experience.**

#### Rationale

- UV workspaces allow each package to have its own `pyproject.toml`, dependencies, and version
- Single `uv sync` installs all packages in development mode
- Cross-package dependencies resolved automatically within workspace
- Shared CI/CD, linting, and documentation infrastructure
- Already successfully using this pattern (current repo structure)

### Options Considered

#### Option 1: UV Workspace Monorepo ✓

**Pros**:
- ✅ Single repository to manage
- ✅ Unified CI/CD pipeline
- ✅ Cross-package changes in single PR
- ✅ Shared dev dependencies and tooling
- ✅ Independent versioning per package

**Cons**:
- ❌ Larger repository size over time
- ❌ Need discipline to maintain package boundaries

#### Option 2: Separate Repositories

**Pros**:
- ✅ Complete isolation between packages
- ✅ Independent release cycles

**Cons**:
- ❌ Coordination overhead for cross-package changes
- ❌ Duplicated CI/CD, linting, documentation setup
- ❌ Version compatibility issues between packages

#### Option 3: Single Monolithic Package

**Pros**:
- ✅ Simplest structure
- ✅ Single version to track

**Cons**:
- ❌ All-or-nothing dependency: projects must install everything
- ❌ Tight coupling makes testing harder
- ❌ Single failure can break entire package

### Consequences

#### Positive

- ✅ **Reduced overhead**: Single PR for cross-package changes
- ✅ **Consistent tooling**: Shared Ruff, BasedPyright, pytest configuration
- ✅ **Easier onboarding**: One repository to clone for all shared utilities

#### Trade-offs

- ⚠️ **Package discipline required**: Must maintain clear boundaries between packages
- ⚠️ **CI complexity**: Need to detect which packages changed for selective testing

#### Technical Debt

- Consider package-specific CI triggers if test times grow significantly

### Implementation

#### Components Affected

1. **Root pyproject.toml**: Workspace configuration with `[tool.uv.workspace]`
2. **packages/*/pyproject.toml**: Individual package configurations
3. **CI/CD**: Single workflow testing all packages

#### Current Structure

```
python-libs/
├── pyproject.toml              # Workspace root
├── packages/
│   ├── cloudflare-auth/
│   │   ├── pyproject.toml      # Independent package
│   │   └── src/cloudflare_auth/
│   └── gcs-utilities/
│       ├── pyproject.toml      # Independent package
│       └── src/gcs_utilities/
└── src/python_libs/            # Shared workspace utilities
```

### Validation

#### Success Criteria

- [x] Multiple packages coexist in single repository
- [x] Each package independently versionable
- [x] `uv sync` resolves all workspace dependencies
- [ ] CI/CD correctly tests affected packages only (future enhancement)

#### Review Schedule

- Initial: Complete (current architecture)
- Ongoing: Review if adding >5 packages

### Related

- [Tech Spec](../tech-spec.md#architecture): Package structure details
- [ADR-002](./adr-002-framework-agnostic-design.md): Framework coupling strategy
