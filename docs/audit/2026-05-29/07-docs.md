# Documentation & Developer Experience Audit

**Date**: 2026-05-29
**Scope**: Documentation and DX only. Read-only.
**Repo**: /home/user/python-libs (uv workspace monorepo, 4 packages + optional `src/python_libs`)

---

## DOC-01: cloudflare-api handoff doc states the package belongs in another repo, yet README ships it as a first-class package

**Severity**: High
**Effort**: S (decide: delete doc or remove package; doc deletion is minutes, the contradiction is the real cost)
**Files**: `docs/cloudflare-api-handoff.md`, `README.md:46`, `packages/cloudflare-api/`

**Evidence**:
- `docs/cloudflare-api-handoff.md:14`: "The package was developed in the wrong repository (`python-libs`) but is ready for migration to `homelab-infra`."
- The doc is a 686-line dated handoff artifact (`docs/cloudflare-api-handoff.md:3` "Date: 2025-12-04", references stale branch `feat/assured-oss-artifact-registry`).
- `README.md:46` lists cloudflare-api as a maintained package; `packages/cloudflare-api/` is a live workspace member (`pyproject.toml:755`).

A reader cannot tell whether cloudflare-api is supported here or is slated to leave. Either the package moved and the doc is stale, or the package stayed and the doc is wrong. Both states are documented simultaneously.

**Recommendation**: Decide ownership. If the package stays, delete the handoff doc and add a normal package README/ADR. If it leaves, that is a code change out of scope here, but the doc should not sit loose in `docs/`.

---

## DOC-02: Python version drift across docs (3.12 vs 3.10-3.14)

**Severity**: Medium
**Effort**: S
**Files**: `CLAUDE.md:36`, `README.md:24`, `docs/index.md:24`, `docs/PYTHON_COMPATIBILITY.md:13`, `pyproject.toml:12`

**Evidence**:
- Truth: `pyproject.toml:12` `requires-python = ">=3.10,<3.15"`, corroborated by `docs/PYTHON_COMPATIBILITY.md:13` ("Python 3.10, 3.11, 3.12, 3.13, and 3.14").
- `CLAUDE.md:36`: "**Python**: 3.12" (single version).
- `README.md:24`: badge "Python 3.12" (README:84 body text is correct: "Python 3.10+ (tested with 3.12)", so the README internally disagrees with its own badge).
- `docs/index.md:24`: "Modern Python 3.12+ support".

Three docs imply 3.12-only or 3.12+; the project supports 3.10-3.14.

**Recommendation**: State "3.10-3.14 (3.12 recommended)" consistently in CLAUDE.md, README badge, and index.md.

---

## DOC-03: CLAUDE.md "Project Structure" describes only `src/python_libs`, omits all 4 packages

**Severity**: High
**Effort**: M (CLAUDE.md is the agent's source of truth; structure, conventions, and commands all assume single-package)
**Files**: `CLAUDE.md:417-434`, `CLAUDE.md:235` (`--cov=src`), `CLAUDE.md:447`

**Evidence**:
- `CLAUDE.md:420` shows the tree rooted at `src/python_libs/` with `core/`, `middleware/`, `utils/` and says nothing about `packages/{cloudflare-auth,cloudflare-api,gcs-utilities,gemini-image}`, which are the real publishable units (`pyproject.toml:750-757`).
- `CLAUDE.md:447` test example: `uv run pytest --cov=src --cov-fail-under=80`. README uses `--cov=python_libs` (README:235,473). The actual coverage target should span the packages, not just `src`.
- `CLAUDE.md` "Project Overview" (line ~30s) calls the project "Shared Python libraries... JWT auth, GCS utilities" but never names the monorepo layout an agent must navigate.

Agents acting on CLAUDE.md will look in `src/python_libs/` for JWT/GCS/Cloudflare code that actually lives under `packages/*/src/`.

**Recommendation**: Replace the CLAUDE.md structure block with the real monorepo layout (mirror README:408-434) and fix coverage examples to cover packages.

---

## DOC-04: CONTRIBUTING.md describes a single-package layout that does not exist

**Severity**: High
**Effort**: M
**Files**: `CONTRIBUTING.md:52-65`, `CONTRIBUTING.md:55`, `CONTRIBUTING.md:239`

**Evidence**:
- `CONTRIBUTING.md:52-65` structure tree shows `src/python_libs/` with `core.py` and `utils/`, no `packages/`.
- `CONTRIBUTING.md:55` references `core.py` (a file). Reality is a package directory `src/python_libs/core/` (`core/config.py`, `core/exceptions.py`). The flat `core.py` does not exist.
- `CONTRIBUTING.md:239` usage example `from python_libs.core import YourModule` is a non-existent symbol.

A new contributor following CONTRIBUTING gets a wrong mental model of where to add code and how to import it.

**Recommendation**: Rewrite the CONTRIBUTING structure section for the monorepo, point contributors to `packages/*/`, and replace fake import examples with a real one (e.g. `from cloudflare_auth import ...`).

---

## DOC-05: API reference documents only the optional shared package, none of the 4 published packages

**Severity**: High
**Effort**: M (needs mkdocstrings path config plus per-package API pages)
**Files**: `docs/api-reference.md:16,25`, `mkdocs.yml:76`

**Evidence**:
- `docs/api-reference.md` contains exactly two autodoc blocks: `::: python_libs.core.config` (line 16) and `::: python_libs.utils.logging` (line 25).
- The 4 shipped packages (`cloudflare_auth`, `cloudflare_api`, `gcs_utilities`, `gemini_image`) have no API reference. `cloudflare_auth` alone exports JWT middleware, CSRF, rate limiter, redis sessions, validators (14 modules under `packages/cloudflare-auth/src/cloudflare_auth/`).
- `mkdocs.yml:76` `paths: [src]` only. mkdocstrings cannot resolve `packages/*/src/*` symbols, so package autodoc would fail even if added.

The documented API is the smallest, least-used part of the repo; the actual product surface is undocumented.

**Recommendation**: Add `packages/*/src` to mkdocstrings `paths`, and add per-package API pages to `docs/api-reference.md` / nav.

---

## DOC-06: Planning README still says "Awaiting Generation" though planning docs are fully written

**Severity**: Medium
**Effort**: S
**Files**: `docs/planning/README.md:37-40`

**Evidence**:
- `docs/planning/README.md:37-40` status table marks project-vision, tech-spec, roadmap, adr as "Awaiting Generation".
- All four exist with real content: `project-vision.md` (112 lines, status: active), `tech-spec.md` (292 lines), `roadmap.md` (269 lines), `adr/` (3 accepted ADRs). These are generated, not pending.

Stale status table; a maintainer may think planning is unstarted and re-run generation, overwriting work.

**Recommendation**: Update the status column to "Complete" / "Active" with dates.

---

## DOC-07: README references `.claude/claude.md` and `.claude/standard/` git subtree that do not exist

**Severity**: Medium
**Effort**: S
**Files**: `README.md:284-313`

**Evidence**:
- `README.md:286` and `:313` reference `.claude/claude.md` (lowercase). Actual file is `.claude/README.md`; no `.claude/claude.md` exists.
- `README.md:287-303` documents a `.claude/standard/` subtree with `CLAUDE.md`, and an update command `git subtree pull --prefix .claude/standard ...`. `.claude/standard/` does not exist (`ls .claude/`: README.md, agents, commands, context, skills, settings.local.json.example).
- Project actually uses cruft + `.standards/` baselines (CLAUDE.md "Cruft Template Updates"), a different mechanism. README's subtree story is for a different template generation.

The documented "Updating Standards" workflow points at missing paths and the wrong tool.

**Recommendation**: Remove the `.claude/standard/` subtree section or replace with the actual cruft/`.standards/` workflow; fix `.claude/claude.md` -> `.claude/README.md`.

---

## DOC-08: index.md and README install instructions reference a non-existent `python-libs` PyPI package

**Severity**: Medium
**Effort**: S
**Files**: `docs/index.md:17`, `README.md:120-126`

**Evidence**:
- `docs/index.md:17` `pip install python-libs`. No such distribution is published; the repo publishes 4 `byronwilliamscpa-*` packages to GCP Artifact Registry (README:61-64), and the root workspace has no production package (`pyproject.toml:22` "Root workspace has no direct production dependencies").
- `README.md:120` Basic Usage: `from python_libs import YourModule` / `module = YourModule()` is placeholder template code, not a real symbol.

A user copying these commands installs nothing usable.

**Recommendation**: Replace `pip install python-libs` with the per-package install (README:61-64) and replace `YourModule` placeholder with a real import (e.g. `from gcs_utilities import ...`).

---

## DOC-09: Missing ADRs for visible architectural decisions (dual middleware, redis sessions)

**Severity**: Medium
**Effort**: M
**Files**: `docs/planning/adr/` (only adr-001..003), `packages/cloudflare-auth/src/cloudflare_auth/`

**Evidence**:
- Existing ADRs cover monorepo (adr-001), framework-agnostic design (adr-002), distribution (adr-003) - all accepted and accurate (`docs/planning/adr/README.md:30-32`).
- Undocumented decisions visible in code:
  - Dual middleware: `middleware.py` AND `middleware_enhanced.py` coexist in `cloudflare_auth`. No ADR explains why two exist or which to use.
  - Dual session backends: `sessions.py` AND `redis_sessions.py`. No ADR on the redis session decision or when to pick which.
- Note `docs/ADRs/` (capital, repo-root docs) holds only `README.md` + `adr-template.md` and no actual ADRs, while real ADRs live in `docs/planning/adr/`. Two ADR homes; README:439 points to `docs/ADRs/README.md` (the empty one), README:447 also points there. The populated location (`docs/planning/adr/`) is not linked from README.

**Recommendation**: Add ADRs for dual-middleware and redis-session choices. Consolidate the two ADR directories or cross-link them; point README at the populated `docs/planning/adr/`.

---

## DOC-10: SECURITY.md required by project standards is absent from repo root

**Severity**: Medium
**Effort**: S
**Files**: (missing) `SECURITY.md`, `CLAUDE.md` "OpenSSF Best Practices" / "Required Project Files", `README.md:489`, `CONTRIBUTING.md:386`

**Evidence**:
- CLAUDE.md "OpenSSF Best Practices Compliance > Required Project Files" lists `SECURITY.md` as mandatory ("All projects must have ... SECURITY.md").
- No `SECURITY.md` at repo root (`ls SECURITY.md`: not found).
- README:489 and CONTRIBUTING:386 redirect to the org-level policy `ByronWilliamsCPA/.github/blob/main/SECURITY.md`. That may be intentional org consolidation, but it conflicts with the repo's own stated requirement and OpenSSF Scorecard (badge at README:5) expects a repo-discoverable policy.

**Recommendation**: Either add a local `SECURITY.md` (even a stub linking to the org policy, which Scorecard accepts) or amend the CLAUDE.md "Required Project Files" list to note org-level delegation.

---

## DOC-11: Large doc set excluded from mkdocs nav (orphaned from rendered site)

**Severity**: Low
**Effort**: M (volume)
**Files**: `mkdocs.yml:160-181`, `docs/`

**Evidence**:
- Nav (`mkdocs.yml:161-181`) includes index, guides/*, api-reference, development/*, project/*. All referenced files exist (no broken nav entries).
- Not in nav, so not reachable on the built site: `docs/OPENSSF_COMPLIANCE.md`, `docs/PROJECT_SETUP.md`, `docs/PYTHON_COMPATIBILITY.md`, `docs/secure.md`, `docs/cloudflare-api-handoff.md`, `docs/template_feedback.md`, and the entire `docs/ADRs/`, `docs/planning/`, `docs/diagrams/`, `docs/_data/` trees.
- `strict: false` (`mkdocs.yml:186`) suppresses warnings, so the omission is silent.

Useful onboarding docs (PROJECT_SETUP, PYTHON_COMPATIBILITY, OPENSSF) never surface to readers of the published site.

**Recommendation**: Add the onboarding/compliance docs and planning/ADR section to nav. Leave handoff/feedback out (or remove them per DOC-01).

---

## DOC-12: CHANGELOG version block placeholder `[0.1.0] - TBD`

**Severity**: Low
**Effort**: S
**Files**: `CHANGELOG.md:24`, `README.md:639`

**Evidence**:
- `CHANGELOG.md:24` `## [0.1.0] - TBD` while README:639 states "Current version: 0.1.0" and all 4 packages declare 0.1.0 (README:45-48). The release date is unfilled.
- Root CHANGELOG tracks workflow migrations only; per-package changelogs exist for cloudflare-auth and gcs-utilities but not cloudflare-api or gemini-image (no CHANGELOG in those package dirs), so changelog coverage is uneven.

**Recommendation**: Set the 0.1.0 date or mark unreleased clearly; add CHANGELOG stubs to the two packages missing them.

---

## Clean areas (one line each)

- mkdocs nav entries: all referenced pages exist; no broken nav targets (`mkdocs.yml:161-181`).
- README-referenced scripts all present (`scripts/validate_assuredoss.py`, `cruft-update.sh`, `check_orphaned_files.py`, `cleanup_conditional_files.py`, etc.).
- ADR-001..003 content is accurate and matches the implemented monorepo/framework-agnostic/distribution decisions.
- `docs/diagrams/publish-workflow.puml` referenced by README:600 exists and matches the inline PlantUML.
- Branch/commit conventions are consistent: CLAUDE.md, CONTRIBUTING (`:260` Conventional Commits, `:314` main branch), and README (`:643-674`) agree.

---

## Summary Table

| ID | Title | Severity | Effort | Files |
|----|-------|----------|--------|-------|
| DOC-01 | Handoff doc says cloudflare-api belongs in another repo while README ships it | High | S | docs/cloudflare-api-handoff.md, README.md:46 |
| DOC-02 | Python version drift (3.12 vs 3.10-3.14) | Medium | S | CLAUDE.md:36, README.md:24, docs/index.md:24, pyproject.toml:12 |
| DOC-03 | CLAUDE.md structure omits all 4 packages | High | M | CLAUDE.md:417-434,447 |
| DOC-04 | CONTRIBUTING describes nonexistent single-package layout | High | M | CONTRIBUTING.md:52-65,239 |
| DOC-05 | API reference covers only optional shared pkg, not the 4 published packages | High | M | docs/api-reference.md:16,25, mkdocs.yml:76 |
| DOC-06 | Planning README "Awaiting Generation" but docs written | Medium | S | docs/planning/README.md:37-40 |
| DOC-07 | README references missing `.claude/claude.md` and `.claude/standard/` subtree | Medium | S | README.md:284-313 |
| DOC-08 | Install/usage references nonexistent `python-libs` PyPI pkg + placeholder import | Medium | S | docs/index.md:17, README.md:120-126 |
| DOC-09 | Missing ADRs for dual middleware / redis sessions; two ADR dirs | Medium | M | docs/planning/adr/, docs/ADRs/, packages/cloudflare-auth/src/ |
| DOC-10 | SECURITY.md required by standards is absent | Medium | S | (missing) SECURITY.md |
| DOC-11 | Many docs excluded from mkdocs nav (orphaned) | Low | M | mkdocs.yml:160-181 |
| DOC-12 | CHANGELOG `[0.1.0] - TBD` placeholder; uneven per-package changelogs | Low | S | CHANGELOG.md:24 |
