---
title: "Architecture"
schema_type: common
status: published
owner: core-maintainer
purpose: "Architecture documentation for Python Libs."
tags:
  - development
  - architecture
---

This document describes the architecture and design decisions for Python Libs.

## Project Structure

```text
python_libs/
├── src/
│   └── python_libs/
│       ├── __init__.py          # Package initialization
│       ├── core/                # Core functionality
│       │   ├── config.py        # Configuration with Pydantic
│       │   └── ...
│       ├── utils/               # Utility modules
│       │   ├── logging.py       # Structured logging
│       │   └── ...
├── tests/                       # Test suite
├── docs/                        # Documentation
└── pyproject.toml               # Project configuration
```text

## Design Principles

### 1. Type Safety

All code is fully typed with BasedPyright strict mode validation.

### 2. Structured Logging

Uses structlog for structured, JSON-formatted logs in production.

### 3. Configuration Management

Pydantic Settings for type-safe configuration from environment variables.

## Dependencies

See `pyproject.toml` for the complete dependency list.

## Architecture Decision Records

See the [ADRs directory](../ADRs/README.md) for documented architecture decisions.
