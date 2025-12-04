---
title: "Usage"
schema_type: common
status: published
owner: core-maintainer
purpose: "Usage guide for Python Libs."
tags:
  - guide
  - usage
---

This guide covers common usage patterns for Python Libs.

## Installation

### From PyPI

```bash
pip install python-libs
```

### From Source

```bash
git clone https://github.com/ByronWilliamsCPA/python-libs
cd python_libs
uv sync --all-extras
```

## Library Usage

### Basic Import

```python
from python_libs import __version__

print(f"Version: {__version__}")
```

### Logging

```python
from python_libs.utils.logging import get_logger, setup_logging

# Setup logging
setup_logging(level="DEBUG", json_logs=False)

# Get a logger
logger = get_logger(__name__)
logger.info("Hello from Python Libs")
```
