---
title: "Python Libs - Development Roadmap"
schema_type: planning
status: active
owner: core-maintainer
purpose: "Document the phased implementation plan and milestones."
tags:
  - planning
  - roadmap
component: Strategy
source: "/plan command generation"
---

## Development Roadmap: Python Libs

> **Status**: Active | **Updated**: 2025-12-04

### TL;DR

Consolidate shared utilities into python-libs across 4 phases: Foundation (complete existing packages), Stabilization (tests, docs, first consumers), Consolidation (refactor for reusability), Expansion (add new packages from pattern analysis), Distribution (Artifact Registry + cookiecutter integration).

## Timeline Overview

```text
Phase 0: Foundation      ████████████████ Complete  - Existing packages working
Phase 1: Stabilization   ░░░░░░░░░░░░░░░░ Planned   - Tests, docs, first consumers
Phase 2: Consolidation   ░░░░░░░░░░░░░░░░ Planned   - Framework-agnostic refactor
Phase 3: Expansion       ░░░░░░░░░░░░░░░░ Planned   - New packages from analysis
Phase 4: Distribution    ░░░░░░░░░░░░░░░░ Planned   - Artifact Registry, template
```

## Milestones

| Milestone | Target | Status | Dependencies |
|-----------|--------|--------|--------------|
| M0: Workspace Setup | Complete | ✅ Done | None |
| M1: First Consumer | Phase 1 | ⏸️ Planned | M0 |
| M2: Framework-Agnostic Auth | Phase 2 | ⏸️ Planned | M1 |
| M3: Logging Package | Phase 3 | ⏸️ Planned | M1 |
| M4: Artifact Registry | Phase 4 | ⏸️ Planned | M1, M2 |

---

## Phase 0: Foundation (Complete)

### Objective

Establish UV workspace monorepo with existing packages migrated.

### Deliverables

- [x] UV workspace configured with `packages/*` members
- [x] gcs-utilities package migrated
- [x] cloudflare-auth package migrated
- [x] Shared workspace utilities in `src/python_libs/`
- [x] CI/CD pipeline configured

### Success Criteria

- ✅ `uv sync` installs all packages
- ✅ Tests pass for both packages
- ✅ Pre-commit hooks working

---

## Phase 1: Stabilization

### Objective

Prepare packages for external consumption with comprehensive tests, documentation, and first consumer migration.

### Deliverables

- [ ] Test coverage ≥ 80% for both packages
- [ ] API documentation generated
- [ ] README with usage examples for each package
- [ ] First consumer project using Git dependencies

### Success Criteria

- ✅ All tests passing with 80%+ coverage
- ✅ Consumer project installs and uses package successfully
- ✅ No breaking changes to existing package APIs

### User Stories

#### US-101: Package Documentation

**As a** developer consuming these packages
**I want** clear documentation with examples
**So that** I can integrate quickly without reading source code

**Acceptance Criteria**:

- [ ] Each package has README with installation and basic usage
- [ ] API reference generated from docstrings
- [ ] Example code tested and working

#### US-102: First Consumer Migration

Migrate one project to validate distribution approach works with Git dependencies.

### Dependencies

- Requires: Phase 0 complete
- Blocks: Phase 2, Phase 3, Phase 4

---

## Phase 2: Consolidation

### Objective

Refactor cloudflare-auth for framework-agnostic core per [ADR-002](./adr/adr-002-framework-agnostic-design.md).

### Deliverables

- [ ] cloudflare-auth/core/ with framework-agnostic logic
- [ ] cloudflare-auth/fastapi/ with FastAPI-specific code
- [ ] Optional dependencies configured (`[fastapi]`, `[redis]`)
- [ ] Migration guide for existing consumers

### Success Criteria

- ✅ Core validation works without FastAPI installed
- ✅ FastAPI middleware works with `[fastapi]` extra
- ✅ Existing consumers work after updating imports
- ✅ Test coverage maintained at 80%+

### User Stories

#### US-201: Framework-Agnostic Core

**As a** CLI tool developer
**I want** to validate Cloudflare tokens without FastAPI
**So that** I can authenticate users in non-web contexts

**Acceptance Criteria**:

- [ ] `from cloudflare_auth.core import CloudflareJWTValidator` works
- [ ] Validation succeeds/fails correctly with test tokens
- [ ] No FastAPI imports in core module

### Dependencies

- Requires: Phase 1 complete (tests, docs baseline)
- Blocks: Phase 4 (Artifact Registry)

---

## Phase 3: Expansion

### Objective

Add new packages based on pattern analysis from organizational repositories.

### Deliverables

- [ ] `python-libs-logging`: Unified structlog configuration
- [ ] Enhanced `python_libs.core.config`: Base Pydantic Settings
- [ ] Enhanced `python_libs.utils.financial`: Decimal precision utilities

### Candidate Packages (Prioritized)

| Package | Source Pattern | Priority | Rationale |
|---------|----------------|----------|-----------|
| Logging utilities | image-preprocessing-detector, data_ingestor | High | Used in every project |
| Config management | Multiple projects | High | Reduces boilerplate |
| Financial utilities | ledgerbase | Medium | Specialized but valuable |
| Schema base classes | RAG projects | Medium | Cross-project validation |
| Device detection | image-preprocessing-detector | Low | RAG-specific, defer |

### Success Criteria

- ✅ Each new package has tests and documentation
- ✅ At least 2 consumer projects adopt each package
- ✅ Reduces code duplication measurably

### User Stories

#### US-301: Logging Package

**As a** developer starting a new project
**I want** consistent structured logging setup
**So that** I don't reinvent logging configuration

**Acceptance Criteria**:

- [ ] Single function call configures structlog + rich
- [ ] JSON output mode for production
- [ ] Rich console output for development
- [ ] Correlation ID support

### Dependencies

- Requires: Phase 1 complete
- Can run in parallel with Phase 2

---

## Phase 4: Distribution

### Objective

Establish mature distribution via Artifact Registry and integrate with cookiecutter template.

### Deliverables

- [ ] Artifact Registry Python repository configured
- [ ] GitHub Actions workflow for publishing
- [ ] Consumer projects migrated from Git to Artifact Registry
- [ ] Cookiecutter template updated to use python-libs

### Success Criteria

- ✅ Packages published to Artifact Registry on release
- ✅ Install time < 10s (vs ~30s for Git)
- ✅ New projects from template use python-libs by default

### User Stories

#### US-401: Artifact Registry Publishing

**As a** package maintainer
**I want** automatic publishing on release
**So that** consumers get updates without manual intervention

**Acceptance Criteria**:

- [ ] GitHub Action publishes on tag push
- [ ] Version matches Git tag
- [ ] Package installable from Artifact Registry URL

#### US-402: Cookiecutter Integration

Update template to include python-libs as optional dependency with package selection prompts.

### Dependencies

- Requires: Phase 1, Phase 2 complete
- Cookiecutter integration can start after Phase 1

---

## Risk Register

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Git dependency performance unacceptable | Medium | Medium | Prioritize Artifact Registry migration |
| Framework-agnostic refactor breaks consumers | Low | High | Deprecation warnings, migration guide |
| Artifact Registry setup complexity | Medium | Low | Detailed documentation, start with Git |
| Low adoption of new packages | Medium | Medium | Migrate own projects first as proof |

## Definition of Done

A feature/package is complete when:

- [ ] Code reviewed and approved
- [ ] Tests written and passing (80%+ coverage)
- [ ] Documentation updated (README, API docs)
- [ ] No linting errors (Ruff, BasedPyright)
- [ ] Changelog updated
- [ ] Merged to main

## Related Documents

- [Project Vision](./project-vision.md)
- [Technical Spec](./tech-spec.md)
- [Architecture Decisions](./adr/)
