---
title: "ADR-003: Private Package Distribution Strategy"
schema_type: planning
status: accepted
owner: core-maintainer
purpose: "Document the decision for private package distribution via Git dependencies evolving to Artifact Registry."
tags:
  - planning
  - architecture
  - decisions
  - distribution
---

## ADR-003: Private Package Distribution Strategy

> **Status**: Accepted
> **Date**: 2025-12-04

### TL;DR

Start with Git dependencies for immediate usability, then migrate to Google Artifact Registry for better caching and integration with Assured OSS infrastructure.

### Context

#### Problem

python-libs packages need to be installable by other organization projects without publishing to public PyPI. Options include:

1. Git dependencies (install directly from GitHub)
2. GitHub Packages (GitHub's package registry)
3. Google Artifact Registry (GCP-native Python repository)
4. Third-party private PyPI (Gemfury, Packagr, etc.)

#### Constraints

- **Technical**: Must work with UV package manager; need authentication for CI/CD
- **Business**: No public distribution; prefer GCP integration (already using GCS, Assured OSS)

#### Significance

Distribution strategy affects install times, caching, security scanning integration, and developer experience. Wrong choice creates friction for package consumers.

### Decision

**We will use Git dependencies initially, migrating to Artifact Registry when caching benefits justify setup complexity.**

#### Rationale

- Git dependencies work immediately with zero infrastructure
- UV has excellent Git dependency support with commit pinning
- Artifact Registry provides proper package caching and Assured OSS integration
- Two-phase approach balances immediate usability with long-term optimization

### Options Considered

#### Option 1: Git Dependencies → Artifact Registry ✓

**Pros**:
- ✅ Immediate availability (Git works now)
- ✅ No infrastructure setup required initially
- ✅ UV supports Git dependencies natively
- ✅ Artifact Registry integrates with existing GCP infrastructure
- ✅ Assured OSS scanning available with Artifact Registry

**Cons**:
- ❌ Git dependencies slower (no package caching)
- ❌ Migration effort when moving to Artifact Registry

#### Option 2: GitHub Packages Only

**Pros**:
- ✅ Integrated with GitHub (no separate service)

**Cons**:
- ❌ Python support is limited (no native pip/UV integration)
- ❌ Requires PAT for authentication
- ❌ No Assured OSS integration

#### Option 3: Third-Party Private PyPI

**Pros**:
- ✅ Drop-in replacement for public PyPI

**Cons**:
- ❌ Additional service to manage and pay for
- ❌ Another credential to manage
- ❌ No GCP integration

#### Option 4: Artifact Registry Only (Skip Git)

**Pros**:
- ✅ Full caching from day one

**Cons**:
- ❌ Significant upfront setup
- ❌ Delays usability until infrastructure ready

### Consequences

#### Positive

- ✅ **Immediate usability**: Projects can use packages today via Git
- ✅ **GCP integration**: Artifact Registry leverages existing infrastructure
- ✅ **Security scanning**: Assured OSS integration when on Artifact Registry

#### Trade-offs

- ⚠️ **Initial performance**: Git dependencies slower than cached packages
- ⚠️ **Migration work**: Need to update consumer projects when switching

#### Technical Debt

- Document migration path from Git to Artifact Registry
- Consumer projects will need dependency updates during migration

### Implementation

#### Phase 1: Git Dependencies (Immediate)

Consumer projects add dependencies like:

```toml
# pyproject.toml
[project]
dependencies = [
    "byronwilliamscpa-gcs-utilities @ git+https://github.com/ByronWilliamsCPA/python-libs.git@v0.1.0#subdirectory=packages/gcs-utilities",
]

# Or using UV sources for development
[tool.uv.sources]
byronwilliamscpa-gcs-utilities = { git = "https://github.com/ByronWilliamsCPA/python-libs.git", subdirectory = "packages/gcs-utilities", tag = "gcs-utilities-v0.1.0" }
```

#### Phase 2: Artifact Registry (Future)

1. Create Python repository in Artifact Registry
2. Configure GitHub Actions to publish on release
3. Update consumer projects to use Artifact Registry URL

```toml
# Future: Artifact Registry
[[tool.uv.index]]
name = "byronwilliamscpa"
url = "https://us-python.pkg.dev/PROJECT_ID/python-libs/simple/"

[project]
dependencies = [
    "byronwilliamscpa-gcs-utilities>=0.1.0",
]
```

#### Components Affected

1. **Consumer pyproject.toml**: Dependency declarations
2. **GitHub Actions**: Publishing workflow (Phase 2)
3. **GCP Infrastructure**: Artifact Registry repository (Phase 2)

### Validation

#### Success Criteria

**Phase 1 (Git)**:
- [ ] Consumer projects can install via Git URL
- [ ] CI/CD pipelines work with Git dependencies
- [ ] Version pinning works correctly

**Phase 2 (Artifact Registry)**:
- [ ] Packages published to Artifact Registry on release
- [ ] Consumer projects install from Artifact Registry
- [ ] Install times improved vs Git dependencies

#### Review Schedule

- Initial: After 3 consumer projects using Git dependencies
- Migration trigger: When CI install times exceed 2 minutes

### Related

- [ADR-001](./adr-001-monorepo-architecture.md): Monorepo structure
- [Tech Spec](../tech-spec.md#infrastructure): CI/CD details
- [Roadmap Phase 3](../roadmap.md#phase-3): Distribution milestone
