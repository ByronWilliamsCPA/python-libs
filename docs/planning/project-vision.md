---
title: "Python Libs - Project Vision & Scope"
schema_type: planning
status: active
owner: core-maintainer
purpose: "Document the project vision, scope, and success criteria."
tags:
  - planning
  - scope
component: Strategy
source: "/plan command generation"
---

## Project Vision & Scope: Python Libs

> **Status**: Active | **Version**: 1.0 | **Updated**: 2025-12-04

## TL;DR

Python Libs is a UV workspace monorepo providing shared, reusable Python utilities for ByronWilliamsCPA projects. It consolidates common patterns (GCS operations, authentication, logging, configuration) to eliminate duplication across repositories and establish organizational standards.

## Problem Statement

### Pain Point

Multiple projects (data_ingestor, image-preprocessing-detector, ledgerbase, magg, PromptCraft) duplicate identical utilities: GCS authentication patterns, structured logging setup, Pydantic configuration management, and error handling. Each project independently maintains these utilities, leading to:

- Inconsistent implementations across projects
- Duplicated bug fixes and security patches
- Increased maintenance burden
- Diverging patterns that complicate developer onboarding

### Target Users

- **Primary**: ByronWilliamsCPA developers working on Python projects
- **Context**: When starting new projects or needing cross-cutting concerns (auth, storage, logging)

### Success Metrics

- **Code Duplication**: Reduce duplicated utility code by 70% across active projects
- **Onboarding Time**: New project setup from template to first commit < 30 minutes
- **Adoption**: 100% of new Python projects use python-libs packages

## Solution Overview

### Core Value

A centralized, well-tested library of shared utilities that any Python project can import, reducing boilerplate and ensuring consistent patterns across the organization.

### Key Capabilities (Current + MVP)

1. **GCS Utilities**: Streamlined Google Cloud Storage operations with base64 credential handling
2. **Cloudflare Auth**: Zero Trust authentication middleware for FastAPI applications
3. **Structured Logging**: Consistent structlog+rich logging setup across all projects
4. **Configuration Management**: Pydantic Settings patterns with environment validation

## Scope Definition

### In Scope (Phase 1 - Foundation)

- ✅ **gcs-utilities**: Complete GCS client wrapper - *Already implemented*
- ✅ **cloudflare-auth**: Cloudflare Access JWT validation - *Already implemented*
- ✅ **Core logging utilities**: Unified structlog configuration
- ✅ **Core exceptions**: Shared exception hierarchy
- ✅ **Configuration patterns**: Base Pydantic Settings classes

### In Scope (Phase 2 - Consolidation)

- ✅ **Framework adapters**: Separate FastAPI-specific code from core logic
- ✅ **Financial utilities**: Decimal precision utilities from ledgerbase patterns
- ✅ **Schema base classes**: Reusable Pydantic models for cross-project validation

### In Scope (Phase 3 - Distribution)

- ✅ **Artifact Registry publishing**: Private package distribution
- ✅ **Cookiecutter integration**: Update template to use python-libs packages
- ✅ **Migration guides**: Help existing projects adopt shared packages

### Out of Scope

- ❌ **Domain-specific logic**: Business logic stays in individual projects
- ❌ **ML/AI model code**: Stays in RAG pipeline projects
- ❌ **Database migrations**: Project-specific, not shared
- 🔄 **Device detection utilities**: Deferred pending RAG pipeline stabilization

## Constraints

### Technical

- **Platform**: Python library packages (installable via UV/pip)
- **Language**: Python 3.10-3.14 (matching cookiecutter template)
- **Architecture**: UV workspace monorepo with independent packages
- **Framework Strategy**: Core logic framework-agnostic, with optional FastAPI adapters

### Business

- **Resources**: Single developer, async development
- **Compatibility**: Must work with existing projects without breaking changes
- **Distribution**: Private packages only (no public PyPI)

## Assumptions to Validate

- [ ] Git dependencies provide acceptable install performance for CI/CD
- [ ] Artifact Registry setup complexity is justified by caching benefits
- [ ] Framework-agnostic refactoring of cloudflare-auth is feasible without major rewrites
- [ ] Existing projects can migrate incrementally without disruption

## Related Documents

- [Architecture Decisions](./adr/)
- [Technical Spec](./tech-spec.md)
- [Roadmap](./roadmap.md)
