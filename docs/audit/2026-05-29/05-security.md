# Security and Secrets Audit: python-libs

Date: 2026-05-29
Scope: Security and secrets only. Read-only defensive review of owner repo.
Branch reviewed: claude/repo-audit-KEOGN
Packages: cloudflare-auth, cloudflare-api, gcs-utilities, gemini-image.

## Method and tooling notes

- `bandit` and `pip-audit` are declared in config but not installed in the venv
  (`uv run bandit` and `uv run pip-audit` both fail to spawn). Dependency CVE
  assessment was done by reading pinned versions in `uv.lock` against known
  advisory cutoffs.
- Secrets review: git history grep (`git log --all -p`), `.env.example`,
  workflow files, source grep.
- Source review: manual read of auth-critical modules plus pattern grep across
  all 53 package Python files.

Headline: no hardcoded secrets, no vulnerable dependencies found, JWT validation
is correct. The real defects are in the CSRF implementation and the IP allowlist
logic in cloudflare-auth.

---

## SEC-01: CSRF validation never verifies the session-bound HMAC token

Severity: High
Effort: M (rewrite generate/validate pair plus tests; design decision on
storage model)
Files:
- `packages/cloudflare-auth/src/cloudflare_auth/csrf.py:72` (generate_token)
- `packages/cloudflare-auth/src/cloudflare_auth/csrf.py:98` (validate_token)
- `packages/cloudflare-auth/src/cloudflare_auth/csrf.py:131` (validate_request)

Evidence:
`generate_token(session_id)` builds an HMAC bound to the session:

```python
data = f"{session_id}{secrets.token_hex(16)}".encode()
token = hmac.new(self.secret_key.encode(), data, digestmod="sha256").hexdigest()
```

But `validate_token` only does:

```python
is_valid = secrets.compare_digest(cookie_token, header_token)
```

It compares the cookie value against the header value. It never re-derives or
verifies the HMAC, never checks the session binding, and never consults
`secret_key`. The scheme degrades to a plain double-submit cookie. The HMAC
binding advertised in the docstring ("prevents length extension attacks",
"bound to session") is not enforced at validation time. Any actor who can place
a matching value in both the cookie and the `X-CSRF-Token` header passes
validation. There is no server-side token store and no per-session check.

Secondary defect, same file: `csrf.py:82` calls `secrets.token_bytes(32)` and
discards the result (dead code). The non-session branch (`csrf.py:93`) returns a
fresh `token_urlsafe(32)` that is also never tied to anything server-side.

Recommendation: pick one model and enforce it. Either (a) verify the HMAC in
`validate_token` by recomputing it from the session id and `secret_key` with
`hmac.compare_digest`, or (b) store issued tokens server-side (the session store
already exists) and validate against that. Remove the dead `token_bytes` call.
Add tests that a cookie==header pair with a wrong/absent session binding is
rejected.

---

## SEC-02: IP allowlist uses naive string prefix matching, not CIDR

Severity: High
Effort: S (replace with `ipaddress` module; cloudflare-api already has correct
logic to copy)
Files:
- `packages/cloudflare-auth/src/cloudflare_auth/middleware.py:193-197`

Evidence:

```python
ip_allowed = any(
    client_ip == allowed_ip
    or client_ip.startswith(allowed_ip.rstrip("/") + ".")
    for allowed_ip in self.settings.allowed_tunnel_ips
)
```

This is a string prefix test, not subnet membership.

- A CIDR entry like `10.0.0.0/8` becomes prefix `10.0.0.0.` after `rstrip("/")`,
  which matches no real address. CIDR entries silently fail closed (deny
  everything they should allow) or, worse, depend on operator confusion.
- A short entry like `10.0` matches `10.0.0.5` and also `10.0X.anything` style
  values, widening the allowlist beyond intent.
- No IPv6 handling.

The sibling package `cloudflare-api` already implements correct validation
(`packages/cloudflare-api/src/cloudflare_api/ip_groups/manager.py` plus
`IPFetcher.validate_ip` / `get_ip_version` exercised in tests), so the codebase
has a correct pattern that this allowlist does not reuse.

Recommendation: use `ipaddress.ip_address(client_ip) in
ipaddress.ip_network(allowed_ip, strict=False)`. Reject unparseable allowlist
entries at config load. Add tests for in-subnet, out-of-subnet, and IPv6.

---

## SEC-03: get_client_ip trusts CF-Connecting-IP regardless of upstream

Severity: Medium
Effort: M (add trusted-proxy gate; touches rate limiter and IP allowlist trust)
Files:
- `packages/cloudflare-auth/src/cloudflare_auth/utils.py:235-263`

Evidence:

```python
cf_connecting_ip = request.headers.get("CF-Connecting-IP")
if cf_connecting_ip:
    return cf_connecting_ip.strip()
```

The header is read unconditionally. The docstring states the security model is
"only trusts CF-Connecting-IP" and "cannot be spoofed by clients", but that
holds only if the app is actually behind Cloudflare and the connection is
verified as coming from Cloudflare. If the service is reachable directly (the
fallback branch acknowledges this is possible: "if not behind Cloudflare ...
development/testing"), any client can set `CF-Connecting-IP` to forge its
source. That value feeds the rate limiter (SEC reference: `middleware.py` /
`middleware_enhanced.py` calls to `get_client_ip` before `is_allowed` /
`record_attempt`) and the IP allowlist (SEC-02), so a spoofed header lets an
attacker rotate IPs to defeat brute-force throttling and potentially satisfy the
tunnel allowlist.

Recommendation: only honor `CF-Connecting-IP` when the direct peer
(`request.client.host`) is in a configured Cloudflare/trusted-proxy range; else
use the socket peer. Make the trust boundary explicit in settings rather than
implicit in a docstring.

---

## SEC-04: Reusable org workflows pinned to mutable @main ref

Severity: Medium
Effort: S (pin to commit SHAs; partially done already)
Files:
- `.github/workflows/ci.yml` (python-qlty-coverage, python-codecov @main)
- `.github/workflows/scorecard.yml`, `reuse.yml`, `docs.yml`,
  `security-analysis.yml`, `python-compatibility.yml`, `sbom.yml`,
  `mutation-testing.yml`, `slsa-provenance.yml` (each calls
  `ByronWilliamsCPA/.github/.github/workflows/*.yml@main`)

Evidence: third-party marketplace actions are correctly SHA-pinned with version
comments (for example `actions/checkout@34e1148... # v4.3.1`,
`step-security/harden-runner@a5ad31d... # v2.19.1`). The first-party reusable
workflows are mostly pinned to the mutable branch `@main`. Two are already
SHA-pinned (`python-sonarcloud.yml` and `python-supplemental-checks.yml` at
`@e8fc83c...`), which shows the intended pattern is not applied consistently.
`pr-validation.yml` and `release.yml` pass `secrets: inherit` into these
workflows, so a force-push or compromise of the `.github` repo's `main` reaches
this repo's secrets.

Recommendation: pin every reusable-workflow `uses:` to a commit SHA with a
version comment, matching the two already done. Renovate can keep them current.

---

## SEC-05: No detect-secrets baseline; secrets scanning depends on local install

Severity: Low
Effort: S (commit a baseline or document the TruffleHog model)
Files:
- repo root (no `.secrets.baseline`)
- `.pre-commit-config.yaml:61-72` (trufflehog local hook)

Evidence: there is no `.secrets.baseline`. The project does not use
detect-secrets; the secret scanner is TruffleHog, invoked via a local hook:

```
command -v trufflehog >/dev/null 2>&1 && trufflehog git ... --fail ||
echo "TruffleHog not installed - skipping"
```

If the developer has not installed TruffleHog, the hook prints "skipping" and
passes. Pre-commit secret scanning is therefore best-effort and silently
no-ops on machines without the binary. This is not baseline drift (no baseline
exists by design), but the detection guarantee is weaker than a committed
baseline or a pinned containerized scanner. Server-side coverage exists via the
CI security workflows, which mitigates.

Recommendation: either add detect-secrets with a committed `.secrets.baseline`,
or make the TruffleHog hook fail (not skip) when the binary is missing in CI
context, so the no-op path cannot mask a finding.

---

## Areas checked and found clean

- Hardcoded secrets: none in code, tests, `.env.example`, configs, or workflows.
  All workflow tokens are `${{ secrets.* }}` references. Git history grep for
  API keys, AWS keys, private-key headers, and bearer tokens returned only
  workflow secret references, never literal values.
- `.env.example` values are placeholders or non-secret config (org names, model
  ids, sample rates). No live credentials.
- JWT validation (`validators.py:144`): explicit `algorithms=[jwt_algorithm]`
  (default `RS256`), signature verified via `PyJWKClient`, audience and issuer
  checks gated on configured values, expiry on by default. No `alg`-confusion
  exposure and no `verify_signature=False` in the auth path. The only
  unverified decode is `get_unverified_claims` (`validators.py:286`), clearly
  documented as debug-only and not invoked by middleware.
- Crypto hygiene: `secrets.token_*` for token generation, `secrets.compare_digest`
  for email/domain/admin comparison (`whitelist.py:272-307`) and CSRF compare.
  Session ids are `secrets.token_urlsafe(32)`.
- FIPS: the only `hashlib.md5` use
  (`packages/cloudflare-api/src/cloudflare_api/ip_groups/manager.py:140`) sets
  `usedforsecurity=False` and is a config-fingerprint, not security. No SHA-1
  for security. Compliant with the CLAUDE.md FIPS rule.
- Insecure patterns: no `pickle`, no `yaml.load`, no `eval`/`exec`, no
  `os.system`, no `subprocess(... shell=True)`, no `subprocess` at all in
  packages. No `verify=False`, no `ssl._create_unverified_context`, no
  `CERT_NONE`. No `debug=True`, no `0.0.0.0` bind, no wildcard CORS in source.
- Broad exception handlers: 23 `except Exception` in package source. Spot-checked
  the security-relevant ones (`redis_sessions.py:381` health ping returns False;
  `whitelist.py:712` admin remove logs via `logger.exception` then returns
  False; `validators.py:308` is the debug decode). All log or are non-auth
  health/admin paths; none silently swallow an auth decision. No bare `except:`.
- Dependencies (from `uv.lock`): cryptography 46.0.3, pyjwt 2.10.1, requests
  2.32.5, urllib3 2.5.0, redis 7.1.0, starlette 0.50.0, fastapi 0.123.8, jinja2
  3.1.6, certifi 2025.11.12, pydantic 2.12.5, setuptools 80.9.0. All at or past
  the fixed versions for known advisories in these packages; no outstanding CVE
  identified for the pinned set.
- GitHub Actions: no `pull_request_target`; no `github.event.*` body/title/ref
  reaching `run:` steps (no script-injection sink). `permissions:` blocks are
  scoped per workflow (`contents: read` default, narrow `write` where needed for
  PR comments, provenance, SBOM). `harden-runner` present on jobs.

---

## Summary table

| ID     | Title                                                      | Severity | Effort | Files |
|--------|------------------------------------------------------------|----------|--------|-------|
| SEC-01 | CSRF validation never verifies session-bound HMAC          | High     | M      | csrf.py:72,98,131 |
| SEC-02 | IP allowlist uses string prefix match, not CIDR            | High     | S      | middleware.py:193-197 |
| SEC-03 | get_client_ip trusts CF-Connecting-IP without proxy gate   | Medium   | M      | utils.py:235-263 |
| SEC-04 | Reusable org workflows pinned to mutable @main             | Medium   | S      | .github/workflows/*.yml |
| SEC-05 | No detect-secrets baseline; TruffleHog hook no-ops if absent| Low      | S      | .pre-commit-config.yaml:61-72 |
