# Security Notes

<!--
SPDX-FileCopyrightText: 2026 Byron Williams <byronawilliams@gmail.com>
SPDX-License-Identifier: MIT
-->

This document records security-relevant observations about the project that
do not fit into `SECURITY.md` (vulnerability reporting policy) but should be
visible to maintainers and downstream consumers.

## Dependency Version Floors Are Unbounded

Every production and dev dependency in `pyproject.toml` (root) and the
per-package `packages/*/pyproject.toml` files uses a bare `>=` floor with
**no upper bound**. Examples:

```toml
"pyjwt>=2.8.0",
"cryptography>=41.0.0",
"google-cloud-storage>=2.10.0",
```

Because there is no `<X.0.0` ceiling, `uv sync` (without a populated
`uv.lock`) or any downstream consumer installing this library may pull in
a future **major** release. Major releases routinely contain breaking
API and behavioural changes — including changes to security defaults —
that can silently regress authentication and storage code paths.

`uv.lock` pins the resolved versions for **this** repository's CI, but
the declared `>=` ranges are what downstream consumers see when they
install `byronwilliamscpa-cloudflare-auth` etc. into their own projects.

**Recommendation:** add an upper bound (e.g. `>=2.8.0,<3.0.0`) to every
runtime dependency, especially the three listed below. Update the bound
deliberately after testing each new major release.

## Three Highest-Risk Dependencies

The risk ranking below considers (a) the blast radius if the dependency
ships a behaviour-changing release and (b) the security sensitivity of
the code path that uses it. All three are direct runtime dependencies of
production code paths.

### 1. `pyjwt>=2.8.0` — JWT signing & validation

- **Where used:** `packages/cloudflare-auth/src/cloudflare_auth/validators.py`
  (`CloudflareJWTValidator.validate_token`) — the only authentication
  gate in front of every protected route that uses `cloudflare-auth`.
- **Why high risk:**
  - PyJWT has historically changed validation defaults across releases
    (e.g. `options` keys, `require` semantics, audience matching,
    handling of the `kid` header). A silent major upgrade could weaken
    signature, expiry, or audience enforcement in ways that are not
    obvious from a passing test suite if tests stub the signing key.
  - The library accepts an `algorithms=` allowlist. If a future version
    changes how that list is interpreted (e.g. treats an empty list
    differently, or alters how `none` is rejected), it could enable
    algorithm-confusion or signature-stripping attacks.
  - Bugs in PyJWT itself — for example, CVE-2022-29217 (key-confusion
    between symmetric and asymmetric algorithms) — have shipped in
    point releases. We must be able to pin to a known-good range and
    upgrade deliberately.
- **Suggested constraint:** `"pyjwt>=2.8.0,<3.0.0"`.

### 2. `cryptography>=41.0.0` — Asymmetric key handling, TLS primitives

- **Where used:** transitively by `PyJWKClient`/`pyjwt` to verify RSA
  and EC signatures on Cloudflare Access tokens; also pulled in by
  `httpx`/`google-cloud-storage` for TLS. Declared explicitly as a
  direct dependency of `cloudflare-auth`.
- **Why high risk:**
  - `cryptography` releases drop deprecated APIs and algorithms on a
    regular cadence (e.g. removal of `Blowfish`/`CAST5`, narrowing of
    `BACKEND` parameters). A major bump can break signature
    verification or downgrade FIPS-mode compatibility — a hard
    requirement called out in `CLAUDE.md`.
  - It is the substrate behind nearly every crypto-sensitive operation
    in the project. Any vulnerability here (e.g. CVE-2023-49083 in
    `cryptography==41.0.x`) can directly compromise JWT validation
    and TLS endpoint verification.
  - The bundled OpenSSL is rebuilt with each minor release. A
    surprise minor bump in transitive resolution can change the
    OpenSSL FIPS provider's behaviour.
- **Suggested constraint:** `"cryptography>=42.0.0,<46.0.0"` (or
  whatever current stable line your FIPS validation has been performed
  against), and pin to the same constraint in every `packages/*`
  `pyproject.toml` that depends on it.

### 3. `google-cloud-storage>=2.10.0` — Data plane for all GCS operations

- **Where used:** `packages/gcs-utilities/src/gcs_utilities/client.py`
  (`GCSClient` — upload, download, list, delete, including
  `delete_directory`).
- **Why high risk:**
  - The 2.x line has already changed authentication default behaviour
    around Application Default Credentials and `GOOGLE_APPLICATION_CREDENTIALS`
    handling between minor releases. A major bump (3.x) could alter
    how service-account JSON files are discovered or how retries are
    performed, leading to either credential leaks or silent
    cross-account access in misconfigured environments.
  - `GCSClient` writes the decoded service-account key to a temporary
    file with `0o600` permissions; any change in how
    `google-cloud-storage` resolves credentials (e.g. preferring
    workload identity in some contexts) could cause that file to be
    bypassed without warning.
  - Bucket listing, deletion, and signed-URL generation all live in
    this SDK. A regression in pagination or filtering could surface
    objects from neighbouring buckets, and a regression in
    `Blob.exists()` semantics could break the
    "exists-before-delete" guard in `GCSClient.delete_file`.
- **Suggested constraint:** `"google-cloud-storage>=2.10.0,<3.0.0"`
  in `packages/gcs-utilities/pyproject.toml` (and the matching dev
  dependency in the root `pyproject.toml`).

## Honourable Mentions

These are also unbounded and worth pinning, but rank below the top three:

| Package | Risk |
|---|---|
| `pydantic>=2.0.0` | v1→v2 was famously breaking; another major bump could change settings/validator semantics. |
| `fastapi>=0.100.0` / `starlette>=0.27.0` | Auth middleware contract has shifted between minors; a major bump can change exception flow used by `cloudflare-auth` middleware. |
| `redis>=5.0.0` | Session store; major bumps have changed connection-pool defaults and TLS verification. |
| `httpx>=0.25.0` | Transport for the JWKS endpoint; HTTP/2 and proxy defaults have shifted between releases. |

## Related Hardening Performed in This Branch

- `CloudflareJWTValidator` now refuses unsafe algorithms (`none`, `HS*`)
  at construction time and explicitly enforces `verify_signature`,
  `verify_exp`, `verify_nbf`, `verify_iat`, and a `require` set for
  `exp`, `iat`, `iss`, `sub`, `aud` on every `jwt.decode` call.
- `GCSClient._sanitize_gcs_path` now rejects control characters,
  backslashes, and `.`/`..` segments.
- `GCSClient.delete_directory` rejects empty prefixes to prevent
  accidental bucket-wide wipes.
- All `.github/workflows/*.yml` reusable-workflow references are pinned
  to a commit SHA rather than `@main`, and `step-security/harden-runner`
  with `egress-policy: audit` has been added to every job that runs
  inline steps.
