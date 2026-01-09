# Contributing to Gemini Image

Thank you for your interest in contributing to the Gemini Image library!

## Getting Started

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- A Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey)

### Development Setup

```bash
# Clone the repository
git clone https://github.com/ByronWilliamsCPA/python-libs.git
cd python-libs/packages/gemini-image

# Create virtual environment and install dependencies
uv sync --all-extras

# Or with pip
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Set up pre-commit hooks (from repo root)
cd ../..
uv run pre-commit install
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src/gemini_image --cov-report=term-missing

# Run specific test file
uv run pytest tests/test_utils.py -v
```

### Code Quality

We use strict linting and type checking:

```bash
# Format code
uv run ruff format src tests

# Lint code
uv run ruff check src tests --fix

# Type check
uv run basedpyright src
```

## Making Changes

### Branch Naming

Use conventional branch names:

- `feat/feature-name` - New features
- `fix/bug-description` - Bug fixes
- `docs/topic` - Documentation updates
- `refactor/component` - Code refactoring
- `test/what-testing` - Test additions

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat(generator): add retry logic for API calls
fix(cli): handle missing API key gracefully
docs(readme): update installation instructions
test(utils): add format detection edge cases
```

### Code Style

- **Line length**: 88 characters (Ruff default)
- **Type hints**: Required for all public functions
- **Docstrings**: Google style, required for public APIs
- **Tests**: Required for new functionality

Example:

```python
def generate_image(
    prompt: str,
    model_key: ModelKey = "pro",
    *,
    verbose: bool = False,
) -> Path | None:
    """Generate an image using Gemini.

    Args:
        prompt: Text description of the image to generate.
        model_key: Model to use ('flash' or 'pro').
        verbose: Show detailed progress output.

    Returns:
        Path to the generated image, or None on failure.

    Raises:
        ValueError: If model_key is invalid.
        APIError: If the Gemini API returns an error.

    """
```

## Pull Request Process

1. **Create a feature branch** from `main`
2. **Make your changes** with tests
3. **Run quality checks**:

   ```bash
   uv run ruff format .
   uv run ruff check .
   uv run basedpyright src
   uv run pytest --cov
   ```

4. **Update documentation** if needed
5. **Submit a pull request** with:
   - Clear description of changes
   - Link to related issue (if any)
   - Test plan or evidence

### PR Requirements

- [ ] All tests pass
- [ ] Code coverage maintained (80%+)
- [ ] No linting errors
- [ ] Type checking passes
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated (for user-facing changes)

## Reporting Issues

### Bug Reports

Include:

- Python version
- Package version
- Minimal reproduction steps
- Expected vs actual behavior
- Error messages/stack traces

### Feature Requests

Include:

- Use case description
- Proposed API (if applicable)
- Alternatives considered

## Questions?

- Open a [GitHub Discussion](https://github.com/ByronWilliamsCPA/python-libs/discussions)
- Check existing issues and discussions first

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
