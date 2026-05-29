# Legacy Code Patterns Audit: python-libs

Date: 2026-05-29
Scope: src/python_libs/ + packages/{cloudflare-auth,cloudflare-api,gcs-utilities,gemini-image}/src
Method: read-only grep + git blame. 61 Python files, 32 non-test source files. requires-python ">=3.10,<3.15".

Overall: this codebase is modern. No deprecated stdlib APIs, no legacy typing generics, no
`.format()`/`%`-string interpolation, almost no `os.path`, no vendored copies. The findings below
are minor modernization gaps, not structural debt.

---

## LEG-01: Naive datetime defaults in dataclass/Pydantic fields

Severity: Medium
Effort: S (two one-line edits plus test adjustment)
Files:
- packages/cloudflare-api/src/cloudflare_api/ip_groups/manager.py:65
- packages/cloudflare-auth/src/cloudflare_auth/models.py:149

Evidence: both fields default to `datetime.now` (naive local time) while every comparison and write
elsewhere uses tz-aware UTC.
- manager.py:65 `fetched_at: datetime = field(default_factory=datetime.now)`, then manager.py:158
compares `datetime.now(tz=timezone.utc) - cache.fetched_at`. Subtracting a naive default from an
aware now raises `TypeError: can't subtract offset-naive and offset-aware datetimes` if the default
is ever used (i.e. a CachedIPs built without explicit `fetched_at`). Other construction sites
(manager.py:190) pass `fetched_at=datetime.now(tz=timezone.utc)`, so the bug is latent.
- models.py:149 `authenticated_at` defaults to `datetime.now` (naive); records local wall-clock for
an auth timestamp while the rest of the auth path is UTC.
- Introduced 2025-12-12 (commit ec92633) for manager.py.

Recommendation: use `default_factory=lambda: datetime.now(tz=timezone.utc)` (or `datetime.UTC` per
LEG-02) for both. The manager case is a correctness bug; the models case is a consistency bug.

---

## LEG-02: timezone.utc instead of datetime.UTC (3.11+ alias)

Severity: Low
Effort: S (mechanical; mind the 3.10 floor)
Files: 9 source/test files, 31 call sites. Concentrated in
packages/cloudflare-auth/src/cloudflare_auth/{sessions.py, models.py, rate_limiter.py,
validators.py, redis_sessions.py} and packages/cloudflare-api/src/cloudflare_api/ip_groups/manager.py.

Evidence: 31 uses of `timezone.utc`; only gemini-image/generator.py uses the newer `datetime.UTC`
shorthand (added 3.11). The repo is inconsistent: one package modern, the rest on the older spelling.

Recommendation: low priority. `datetime.UTC` requires 3.11; requires-python floor is 3.10, so a
straight swap would break 3.10. Either keep `timezone.utc` everywhere for consistency (preferred
given the floor), or raise the floor to 3.11 and standardize on `UTC`. Pick one; do not leave it
mixed.

---

## LEG-03: os.path single use where pathlib is house standard

Severity: Low
Effort: S
Files: packages/gcs-utilities/src/gcs_utilities/client.py:717

Evidence: one occurrence repo-wide:
`if self._credentials_path and os.path.exists(self._credentials_path):`. CLAUDE.md states pathlib is
the house standard. `import os` at client.py:8 exists for this and other `os` uses.

Recommendation: replace with `Path(self._credentials_path).exists()`. Trivial. Verify whether
`import os` is still needed afterward (other `os.*` calls may remain in the file).

---

## LEG-04: Parallel basic/enhanced middleware and session implementations

Severity: Low
Effort: M (requires product decision, not just code)
Files:
- packages/cloudflare-auth/src/cloudflare_auth/middleware.py (569 lines)
- packages/cloudflare-auth/src/cloudflare_auth/middleware_enhanced.py (740 lines)
- packages/cloudflare-auth/src/cloudflare_auth/sessions.py (321 lines)
- packages/cloudflare-auth/src/cloudflare_auth/redis_sessions.py (383 lines)

Evidence: `CloudflareAuthMiddleware` and `CloudflareAuthMiddlewareEnhanced` are both exported from
`__init__.py` (lines 38-44, 78-79) and share overlapping logic (rate-limit gating, JWT header
checks, auth-failure paths). git log shows both edited in the same recent commits (52e5c27,
476736c, 2249de5), so the "enhanced" file is NOT a stale fork: it is an actively maintained second
variant. Same pattern for in-memory `sessions.py` vs `redis_sessions.py`.

This is not classic dead/legacy code (both are live and exported). It is a duplication risk: the two
middleware classes drift, and the recent "add rate limiting to all failure paths" fix (52e5c27) had
to touch both. Flagged because "enhanced"/non-enhanced naming is a common precursor to one becoming
abandoned.

Recommendation: confirm both are intentionally supported. If yes, factor shared request-handling
into a common base or helper module to stop double-patching. If the basic variant is legacy, mark it
deprecated and plan removal. Sessions/redis_sessions split is legitimate (backend choice); leave it.

---

## Clean patterns (one line each)

- Deprecated stdlib APIs: clean. Zero `datetime.utcnow()`, `pkg_resources`, `asyncio.get_event_loop()`.
- Legacy typing generics: clean. Zero `Optional[`, `Union[`, `List[`, `Dict[`, `Tuple[`, `Set[`; only
  `Any`, `Literal`, `TypedDict`, `TYPE_CHECKING` imported from typing; 8 files use
  `from __future__ import annotations`. PEP 585/604 builtins used throughout.
- Pre-f-string formatting: clean. Zero `.format()`. All 100 `%s`/`%d` hits are lazy-logging format
  args (correct per ruff G rule), strftime codes, or argparse `%(prog)s`. None are `%`-interpolation.
- Commented-out / dead code: clean. The single code-shaped comment (redis_sessions.py:220) is an
  explanatory note, not dead code. 4 TODO/HACK-pattern hits, all benign (one test TODO at
  gcs-utilities/tests/test_exceptions.py:9; rest are "hacker"/"xxxx" string literals in tests).
- Vendored copies: clean. No vendor/_vendor dirs, no copied utility modules.
- Resolved feature flags: clean. All `enable_*` matches are live runtime constructor params
  (`enable_rate_limiting`, `enable_sessions`, `enable_hsts`) with conditional logic; no resolved/dead
  toggles, no `if False:` blocks.

---

## Summary table

| ID | Title | Severity | Effort | Files |
|----|-------|----------|--------|-------|
| LEG-01 | Naive datetime defaults in field factories | Medium | S | manager.py:65, models.py:149 |
| LEG-02 | timezone.utc vs datetime.UTC inconsistency | Low | S | 9 files, 31 sites |
| LEG-03 | os.path use vs pathlib house standard | Low | S | gcs-utilities/client.py:717 |
| LEG-04 | Parallel basic/enhanced middleware duplication | Low | M | middleware.py, middleware_enhanced.py (+ sessions split) |
