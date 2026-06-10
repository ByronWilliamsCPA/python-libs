# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Hardened `CloudflareJWTValidator`: enforce an allowlist of asymmetric
  JWT algorithms (`RS*`/`ES*`/`PS*`) at construction and against the
  unverified token header, rejecting `none` and HS* to block
  algorithm-confusion attacks.
- JWT decode now explicitly enables `verify_signature`, `verify_exp`,
  `verify_nbf`, `verify_iat`, and a `require` set for `exp`/`iat`/
  `iss`/`sub`/`aud`. Added 30s leeway for clock skew. Removed the
  `verify_exp=False` keyword from `validate_token` /
  `validate_token_async`.
- Replaced blanket `except Exception` in JWT validation with specific
  PyJWT exception handlers; `get_unverified_claims` now logs a warning
  on every call.
- Hardened `GCSClient._sanitize_gcs_path`: reject control characters,
  backslashes, and `.`/`..` segments. Reject null bytes in local paths.
- `GCSClient.upload_directory` re-sanitizes the joined GCS path so
  unusual filenames cannot reintroduce traversal sequences.
- `GCSClient.delete_directory` rejects empty / whitespace-only prefixes
  to prevent accidental bucket-wide wipes.
- Pinned all `ByronWilliamsCPA/.github` reusable-workflow references in
  `.github/workflows/*.yml` to a commit SHA instead of `@main`.
- Reduced workflow-level `permissions:` to `contents: read` and granted
  elevated rights only to the jobs that need them.
- Added `step-security/harden-runner` with `egress-policy: audit` to
  every workflow job that runs inline steps.
- Added `SECURITY-NOTES.md` documenting the unbounded `>=` dependency
  ranges and the three highest-risk dependencies (`pyjwt`,
  `cryptography`, `google-cloud-storage`).

### Changed

- Migrated `sonarcloud.yml` to use `python-sonarcloud.yml` reusable workflow
- Migrated `pr-validation.yml` to use `python-supplemental-checks.yml` reusable workflow
- Removed dependency on deprecated `python-pr-validation.yml` workflow

### Fixed

- Restored the required status-check contexts the org rulesets enforce, which had
  drifted out of sync during the monorepo conversion and were silently blocking
  every open PR (the missing contexts sat permanently pending):
  - `security-analysis.yml`: removed the unsupported `run-safety` input that caused a
    workflow `startup_failure`, and added the `Security Gate Validation` job.
  - `reuse.yml`: emit the bare `Check REUSE Compliance` context via a standalone
    `fsfe/reuse-action` job instead of the reusable workflow's slash-prefixed name.
  - `pr-validation.yml`: added the `Dependency & Standards Validation` summary job.
- Resolved CodeQL false positive for incomplete URL substring sanitization in test file

### Added

- Initial project setup and structure

## [0.1.0] - TBD

### Added

- Initial project structure with Poetry package management
- Pydantic v2 JSON schema validation
- Structured logging with structlog and rich console output
- Pre-commit hooks (Ruff format, Ruff lint, BasedPyright, Bandit, Safety)
- Comprehensive test suite with pytest
- GitHub Actions CI/CD pipeline with quality gates
- CLI tool foundation
- License

### Documentation

- README with project overview and quick start
- CONTRIBUTING guidelines with development workflow
- References to ByronWilliamsCPA org-level Security Policy
- References to ByronWilliamsCPA org-level Code of Conduct

### Infrastructure

- Poetry dependency management with lock file
- pytest test framework with coverage reporting
- GitHub issue tracking and templates
- Automated dependency security scanning (Safety, Bandit)
- Code quality enforcement (Ruff, BasedPyright)
- CI/CD pipeline with multiple quality gates

### Security

- Bandit security linting
- Safety dependency vulnerability scanning
- Pre-commit hooks for security validation

[Unreleased]: https://github.com/ByronWilliamsCPA/python_libs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ByronWilliamsCPA/python_libs/releases/tag/v0.1.0
