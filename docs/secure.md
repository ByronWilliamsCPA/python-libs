# python-libs Publishing Handoff Document

> **Repository:** [ByronWilliamsCPA/python-libs](https://github.com/ByronWilliamsCPA/python-libs)  
> **Last Updated:** 2025-12-04  
> **Status:** Ready for Implementation

## Overview

This document provides everything needed to set up publishing for the `python-libs` monorepo to GCP Artifact Registry, with secrets managed via Infisical.

### What's Already Done ✅

| Component | Status | Details |
|-----------|--------|---------|
| Artifact Registry | ✅ Created | `us-central1-python.pkg.dev/assured-oss-457903/python-libs` |
| Service Account | ✅ Configured | `assured-oss-accessor@assured-oss-457903.iam.gserviceaccount.com` (has writer access) |
| Infisical Server | ✅ Running | https://secrets.byronwilliamscpa.com |
| Package Structure | ✅ Complete | `cloudflare-auth` and `gcs-utilities` packages ready |

### What You Need to Do

1. Configure Infisical project and secrets
2. Create machine identity for GitHub Actions
3. Add Infisical credentials to GitHub
4. Add the publishing workflow
5. Fix cloudflare-auth imports
6. Test publish with gcs-utilities
7. Publish cloudflare-auth

---

## Part 1: Infisical Setup

### 1.1 Create Project

1. Go to https://secrets.byronwilliamscpa.com
2. Click **+ Add New Project**
3. Name: `python-libs`
4. Click **Create Project**

### 1.2 Add GCP Secret

1. Select **prod** environment
2. Click **+ Add Secret**
3. Configure:
   - **Key:** `GCP_SA_KEY_BASE64`
   - **Value:** (see command below)

```bash
# Generate base64-encoded service account key
gcloud iam service-accounts keys create /tmp/sa-key.json \
    --iam-account=assured-oss-accessor@assured-oss-457903.iam.gserviceaccount.com

# Copy this output as the secret value
cat /tmp/sa-key.json | base64 -w 0

# Clean up (important!)
rm /tmp/sa-key.json
```

### 1.3 Create Machine Identity

1. Go to **Organization Settings** → **Machine Identities**
2. Click **+ Create Identity**
3. Name: `github-actions-python-libs`
4. Click **Create**

### 1.4 Add Universal Auth

1. Select the machine identity you just created
2. Go to **Authentication** tab
3. Click **+ Add Authentication Method**
4. Select **Universal Auth**
5. Configure:
   - **Access Token TTL:** `300` (5 minutes)
   - **Max TTL:** `86400` (24 hours)
   - **Access Token Max Uses:** `0` (unlimited)
6. Click **Create**
7. **⚠️ IMPORTANT: Copy and save the Client ID and Client Secret now!**

### 1.5 Grant Project Access

1. Go back to **Projects** → **python-libs**
2. Click **Access Control** in sidebar
3. Click **+ Add Member**
4. Select **Machine Identity** tab
5. Choose `github-actions-python-libs`
6. Role: **Member**
7. Environments: Check **prod**
8. Click **Add**

---

## Part 2: GitHub Configuration

### 2.1 Add Repository Secrets

1. Go to https://github.com/ByronWilliamsCPA/python-libs
2. Click **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add these two secrets:

| Name | Value |
|------|-------|
| `INFISICAL_CLIENT_ID` | (Client ID from step 1.4) |
| `INFISICAL_CLIENT_SECRET` | (Client Secret from step 1.4) |

### 2.2 Add Publishing Workflow

Create `.github/workflows/publish.yml` with this content:

```yaml
# .github/workflows/publish.yml
# Publishes packages to GCP Artifact Registry when tags are pushed
# Secrets are fetched from Infisical

name: Publish Package

on:
  push:
    tags:
      - 'cloudflare-auth-v*'
      - 'gcs-utilities-v*'

permissions:
  contents: read

env:
  INFISICAL_DOMAIN: https://secrets.byronwilliamscpa.com
  INFISICAL_PROJECT: python-libs
  INFISICAL_ENV: prod
  ARTIFACT_REGISTRY_URL: https://us-central1-python.pkg.dev/assured-oss-457903/python-libs/

jobs:
  determine-package:
    runs-on: ubuntu-latest
    outputs:
      package_dir: ${{ steps.parse.outputs.package_dir }}
      package_name: ${{ steps.parse.outputs.package_name }}
      version: ${{ steps.parse.outputs.version }}
    steps:
      - name: Parse tag
        id: parse
        run: |
          TAG="${{ github.ref_name }}"
          echo "Processing tag: $TAG"
          
          if [[ "$TAG" == cloudflare-auth-v* ]]; then
            echo "package_dir=packages/cloudflare-auth" >> $GITHUB_OUTPUT
            echo "package_name=byronwilliamscpa-cloudflare-auth" >> $GITHUB_OUTPUT
            echo "version=${TAG#cloudflare-auth-v}" >> $GITHUB_OUTPUT
          elif [[ "$TAG" == gcs-utilities-v* ]]; then
            echo "package_dir=packages/gcs-utilities" >> $GITHUB_OUTPUT
            echo "package_name=byronwilliamscpa-gcs-utilities" >> $GITHUB_OUTPUT
            echo "version=${TAG#gcs-utilities-v}" >> $GITHUB_OUTPUT
          else
            echo "::error::Unknown tag format: $TAG"
            exit 1
          fi

  build-and-publish:
    needs: determine-package
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Fetch secrets from Infisical
        uses: Infisical/secrets-action@v1.0.7
        with:
          client-id: ${{ secrets.INFISICAL_CLIENT_ID }}
          client-secret: ${{ secrets.INFISICAL_CLIENT_SECRET }}
          env-slug: ${{ env.INFISICAL_ENV }}
          project-slug: ${{ env.INFISICAL_PROJECT }}
          domain: ${{ env.INFISICAL_DOMAIN }}

      - name: Install uv
        uses: astral-sh/setup-uv@6b9c6063abd6010835644d4c2e1bef4cf5cd0fca # v6.0.1
        with:
          enable-cache: true

      - name: Set up Python
        run: uv python install 3.12

      - name: Verify version matches tag
        working-directory: ${{ needs.determine-package.outputs.package_dir }}
        run: |
          TOML_VERSION=$(grep '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/')
          TAG_VERSION="${{ needs.determine-package.outputs.version }}"
          if [[ "$TOML_VERSION" != "$TAG_VERSION" ]]; then
            echo "::error::Version mismatch! pyproject.toml=$TOML_VERSION, tag=$TAG_VERSION"
            exit 1
          fi

      - name: Authenticate to Google Cloud
        uses: google-github-actions/auth@71f986410dfbc7added4569d411d040a91dc6935 # v2.1.8
        with:
          credentials_json: ${{ env.GCP_SA_KEY_BASE64 }}

      - name: Install keyring for Artifact Registry
        run: pip install keyrings.google-artifactregistry-auth

      - name: Build package
        working-directory: ${{ needs.determine-package.outputs.package_dir }}
        run: uv build

      - name: Publish to Artifact Registry
        working-directory: ${{ needs.determine-package.outputs.package_dir }}
        run: uv publish --publish-url ${{ env.ARTIFACT_REGISTRY_URL }}

      - name: Job summary
        run: |
          echo "## 📦 Published: ${{ needs.determine-package.outputs.package_name }} v${{ needs.determine-package.outputs.version }}" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "Registry: \`us-central1-python.pkg.dev/assured-oss-457903/python-libs\`" >> $GITHUB_STEP_SUMMARY
```

---

## Part 3: Fix cloudflare-auth Imports

The `cloudflare-auth` package has imports that reference `src.cloudflare_auth` and `src.config.settings`. These must be fixed before publishing.

### 3.1 Add settings.py

Create `packages/cloudflare-auth/src/cloudflare_auth/settings.py`:

```python
"""Cloudflare Access configuration settings.

Hybrid approach: reads from environment by default, but accepts injected settings.
"""

from functools import lru_cache
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CloudflareSettings(BaseSettings):
    """Configuration for Cloudflare Access authentication."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )
    
    # Required
    cloudflare_team_domain: str = Field(default="", alias="CLOUDFLARE_TEAM_DOMAIN")
    cloudflare_audience_tag: str = Field(default="", alias="CLOUDFLARE_AUDIENCE_TAG")
    cloudflare_enabled: bool = Field(default=True, alias="CLOUDFLARE_ENABLED")
    
    # Headers
    jwt_header_name: str = Field(default="Cf-Access-Jwt-Assertion", alias="CF_JWT_HEADER")
    email_header_name: str = Field(default="Cf-Access-Authenticated-User-Email", alias="CF_EMAIL_HEADER")
    
    # Security
    require_email_verification: bool = Field(default=True, alias="CF_REQUIRE_EMAIL_VERIFICATION")
    log_auth_failures: bool = Field(default=True, alias="CF_LOG_AUTH_FAILURES")
    require_cloudflare_headers: bool = Field(default=True, alias="CF_REQUIRE_CLOUDFLARE_HEADERS")
    
    # Access control
    allowed_email_domains: list[str] = Field(default_factory=list, alias="CF_ALLOWED_EMAIL_DOMAINS")
    allowed_tunnel_ips: list[str] = Field(default_factory=list, alias="CF_ALLOWED_TUNNEL_IPS")
    
    # Cookies
    cookie_domain: Optional[str] = Field(default=None, alias="CF_COOKIE_DOMAIN")
    cookie_path: str = Field(default="/", alias="CF_COOKIE_PATH")
    cookie_secure: bool = Field(default=True, alias="CF_COOKIE_SECURE")
    cookie_samesite: str = Field(default="lax", alias="CF_COOKIE_SAMESITE")
    
    # JWT
    jwt_algorithm: str = Field(default="RS256", alias="CF_JWT_ALGORITHM")
    jwt_cache_max_keys: int = Field(default=16, alias="CF_JWT_CACHE_MAX_KEYS")
    
    @field_validator("allowed_email_domains", "allowed_tunnel_ips", mode="before")
    @classmethod
    def parse_comma_separated(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()] if v.strip() else []
        return v or []
    
    @property
    def issuer(self) -> str:
        if not self.cloudflare_team_domain:
            return ""
        domain = self.cloudflare_team_domain.rstrip("/")
        return f"https://{domain}" if not domain.startswith("https://") else domain
    
    @property
    def certs_url(self) -> str:
        return f"{self.issuer}/cdn-cgi/access/certs" if self.issuer else ""
    
    def is_email_allowed(self, email: str) -> bool:
        if not self.allowed_email_domains:
            return True
        if "@" not in email:
            return False
        domain = email.split("@")[-1].lower()
        return domain in [d.lower() for d in self.allowed_email_domains]


_settings_instance: Optional[CloudflareSettings] = None


def get_cloudflare_settings() -> CloudflareSettings:
    """Get default settings (singleton, reads from environment)."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = CloudflareSettings()
    return _settings_instance


def reset_settings() -> None:
    """Reset singleton (for testing)."""
    global _settings_instance
    _settings_instance = None
```

### 3.2 Update pyproject.toml

Add `pydantic-settings` to dependencies in `packages/cloudflare-auth/pyproject.toml`:

```toml
dependencies = [
    "pydantic>=2.0.0",
    "pydantic-settings>=2.0.0",  # ADD THIS LINE
    "pyjwt>=2.8.0",
    "cryptography>=41.0.0",
    "httpx>=0.25.0",
]
```

### 3.3 Fix Imports

Update these files to change imports from `src.` to relative/package imports:

**Files to update:**
- `__init__.py`
- `middleware.py`
- `middleware_enhanced.py`
- `validators.py`

**Find and replace:**

| Find | Replace With |
|------|--------------|
| `from src.cloudflare_auth.` | `from cloudflare_auth.` or `from .` |
| `from src.config.settings import CloudflareSettings, get_cloudflare_settings` | `from cloudflare_auth.settings import CloudflareSettings, get_cloudflare_settings` |

**Example for `__init__.py`:**

```python
# Change FROM:
from src.cloudflare_auth.middleware import CloudflareAuthMiddleware, get_current_user

# Change TO:
from cloudflare_auth.middleware import CloudflareAuthMiddleware, get_current_user
# OR use relative imports:
from .middleware import CloudflareAuthMiddleware, get_current_user
```

### 3.4 Test Locally

```bash
cd packages/cloudflare-auth
uv sync
uv build

# Verify wheel contents
unzip -l dist/*.whl
```

---

## Part 4: Publishing Packages

### 4.1 First Publish: gcs-utilities (Test Run)

Start with `gcs-utilities` since it has no import issues:

```bash
# Ensure you're on main with latest changes
git checkout main
git pull

# Tag the release
git tag gcs-utilities-v0.1.0
git push --tags
```

**Watch the Actions tab.** The workflow should:
1. ✅ Parse the tag
2. ✅ Fetch secrets from Infisical
3. ✅ Authenticate to GCP
4. ✅ Build the package
5. ✅ Publish to Artifact Registry

### 4.2 Verify Publication

```bash
# Install keyring
pip install keyrings.google-artifactregistry-auth

# Authenticate
gcloud auth application-default login

# Check package is available
pip index versions byronwilliamscpa-gcs-utilities \
    --index-url https://us-central1-python.pkg.dev/assured-oss-457903/python-libs/simple
```

### 4.3 Publish cloudflare-auth

After fixing imports (Part 3):

```bash
git add -A
git commit -m "fix: update imports for package distribution"
git push

git tag cloudflare-auth-v0.1.0
git push --tags
```

---

## Part 5: Adding New Packages

To add a new package to the monorepo:

### 5.1 Create Package Structure

```bash
mkdir -p packages/new-package/src/new_package
mkdir -p packages/new-package/tests
```

### 5.2 Create pyproject.toml

```toml
[project]
name = "byronwilliamscpa-new-package"
version = "0.1.0"
description = "Description here"
readme = "README.md"
requires-python = ">=3.10,<3.15"
license = {text = "MIT"}
authors = [{name = "Byron Williams", email = "byronawilliams@gmail.com"}]

dependencies = []

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/new_package"]

[tool.semantic_release]
version_toml = ["pyproject.toml:project.version"]
tag_format = "new-package-v{version}"
```

### 5.3 Update Workflow

Add the new tag pattern to `.github/workflows/publish.yml`:

```yaml
on:
  push:
    tags:
      - 'cloudflare-auth-v*'
      - 'gcs-utilities-v*'
      - 'new-package-v*'  # ADD THIS
```

Update the parse step:

```yaml
elif [[ "$TAG" == new-package-v* ]]; then
  echo "package_dir=packages/new-package" >> $GITHUB_OUTPUT
  echo "package_name=byronwilliamscpa-new-package" >> $GITHUB_OUTPUT
  echo "version=${TAG#new-package-v}" >> $GITHUB_OUTPUT
```

---

## Troubleshooting

### "Infisical: Access denied"

- Verify machine identity has access to the project
- Check environment is `prod` (not `dev`)
- Verify Client ID and Secret are correct

### "GCP: Permission denied"

- The secret `GCP_SA_KEY_BASE64` must be valid base64
- Service account needs `roles/artifactregistry.writer` on the repository

### "Version mismatch" error

- Update `version` in `pyproject.toml` before tagging
- Tag format must match: `{package}-v{version}`

### Build fails with import errors

- Ensure all `src.` imports are changed to relative/package imports
- Run `uv build` locally to test before pushing

---

## Quick Reference

| Item | Value |
|------|-------|
| **Artifact Registry** | `us-central1-python.pkg.dev/assured-oss-457903/python-libs` |
| **Service Account** | `assured-oss-accessor@assured-oss-457903.iam.gserviceaccount.com` |
| **Infisical URL** | https://secrets.byronwilliamscpa.com |
| **Infisical Project** | `python-libs` |
| **GitHub Secrets** | `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET` |

### Tag Formats

| Package | Tag Format | Example |
|---------|------------|---------|
| cloudflare-auth | `cloudflare-auth-v{version}` | `cloudflare-auth-v0.1.0` |
| gcs-utilities | `gcs-utilities-v{version}` | `gcs-utilities-v1.2.3` |

---

## Contacts

- **Infrastructure Questions:** Byron Williams
- **Infisical Issues:** Check https://secrets.byronwilliamscpa.com status
- **GCP Issues:** Check `assured-oss-457903` project in GCP Console