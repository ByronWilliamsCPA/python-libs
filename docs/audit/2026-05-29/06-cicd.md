# CI/CD and Tooling Audit - 2026-05-29

Scope: `.github/workflows/` (20 workflows + README), static-analysis configs, pre-commit, noxfile. Read-only.

Headline: action pinning is in good shape (all 41 external action invocations SHA-pinned, no deprecated `v3` artifact actions, no `set-output`). The real problems are coverage gaps, broken coverage-artifact handoff, config drift between `src/` and `packages/`, scanner redundancy, and a hollowed-out CI gate that does not enforce coverage.

---

## CI-01 CI tests only 2 of 4 packages

**Severity: Critical. Effort: M** (add two matrix entries + path filters; basis: mirror existing jobs, retest).

Files: `.github/workflows/ci.yml:32-156`, `packages/`

Evidence: `packages/` contains `cloudflare-api`, `cloudflare-auth`, `gcs-utilities`, `gemini-image` (4 dirs). `ci.yml` defines test jobs only for `test-cloudflare-auth` (line 63) and `test-gcs-utilities` (line 111). `detect-changes` filters (lines 51-60) list only `cloudflare-auth` and `gcs-utilities`. `publish-artifact-registry.yml:96,124-134` confirms `cloudflare-api` and `gemini-image` are real, publishable packages. They are published to Artifact Registry with zero tests, type-check, or lint in CI.

Recommendation: Add `test-cloudflare-api` and `test-gemini-image` jobs and path filters mirroring the existing two. Wire both into `ci-gate` needs (line 213).

---

## CI-02 Coverage gate disabled in CI

**Severity: High. Effort: S.**

Files: `.github/workflows/ci.yml:94,142`, `pyproject.toml:595,648`, `noxfile.py:310,332`

Evidence: Both CI test jobs pass `--cov-fail-under=0` (lines 94, 142) plus `--no-cov-on-fail`. The house standard is 80% (CLAUDE.md, `pyproject.toml:595` `--cov-fail-under=80`, `[tool.coverage] fail-under = 85` at line 648, `release.yml:65` uses `--cov-fail-under=80`). CI therefore enforces 0% while release enforces 80%. A regression that drops coverage to near-zero passes CI and only fails at release time. The `ci-gate` (lines 210-225) only checks job `result == failure`; with fail-under=0 the coverage threshold can never trip it.

Recommendation: Set `--cov-fail-under=80` in both CI jobs, or download artifacts and enforce a combined threshold in `coverage`/`ci-gate`.

---

## CI-03 Coverage artifact name mismatch breaks downstream uploads

**Severity: High. Effort: S.**

Files: `.github/workflows/ci.yml:107,155`; `codecov.yml:28`; `qlty.yml:23`; `coverage.yml:28`

Evidence: CI uploads artifacts named `coverage-cloudflare-auth` (line 107) and `coverage-gcs-utilities` (line 155). The `workflow_run` consumers expect a single artifact named `coverage-reports`: `codecov.yml:28` `artifact-name: 'coverage-reports'`, `qlty.yml:23` and `coverage.yml:28` `coverage-artifact-name: coverage-reports`. No CI step produces `coverage-reports`. The post-CI Codecov and Qlty uploads will find no matching artifact and silently process nothing.

Recommendation: Either rename CI artifacts to `coverage-reports` (merge both XMLs into one artifact) or change the three consumers to the pattern `coverage-*`.

---

## CI-04 Non-blocking security and quality steps

**Severity: High. Effort: S.**

Files: `.github/workflows/ci.yml:181`; `pr-validation.yml:80`; `codecov.yml`/`ci.yml:203`

Evidence:
- `ci.yml:181` Bandit runs with `|| true`, so any finding is swallowed; the Security Scan job always passes. This contradicts CLAUDE.md "ALL security findings should be addressed" and "fail on HIGH/CRITICAL by default".
- `pr-validation.yml:80` vulture runs with `|| true` (acceptable for dead-code advisory, lower concern).
- `ci.yml:203` Codecov `fail_ci_if_error: false` - upload failures are silent (defensible, but combined with CI-03 means coverage reporting can fully break unnoticed).

Recommendation: Remove `|| true` from the Bandit step (line 181). Bandit config already skips test asserts via `[tool.bandit.assert_used]`, so a real failure is signal.

---

## CI-05 Static-analysis Python-version drift

**Severity: Medium. Effort: M** (decide a floor, align 5 files, retest matrix).

Files: `pyproject.toml:12,153,502`; `noxfile.py:295,407,420`; `sonar-project.properties:22`; `.github/workflows/python-compatibility.yml`

Evidence: `requires-python = ">=3.10,<3.15"` (pyproject:12). But:
- Ruff `target-version = "py312"` (pyproject:153) - lints as if min is 3.12, so 3.10/3.11-incompatible syntax is not flagged.
- BasedPyright `pythonVersion = "3.12"` (pyproject:502) - type-checks against 3.12 only.
- SonarCloud `sonar.python.version=3.12` (sonar-project.properties:22).
- noxfile `test`/`lint`/`typecheck` matrices include `3.14` (lines 295, 407, 420-421) which is allowed by `<3.15` but absent from CI's matrix (`ci.yml:71` stops at `3.13`) and from `python-compatibility.yml` (`["3.10".."3.13"]`).

Net: code claims 3.10-3.14 support; static tools validate only 3.12; CI tests 3.10-3.13; nox tests 3.10-3.14. Four different version sets.

Recommendation: Pick one supported floor. If 3.10 is the real floor, set Ruff `target-version = "py310"` so down-level checks fire. Align nox, CI, and compat matrices (drop or add 3.14 consistently).

---

## CI-06 Pre-commit diverges from CI (no Ruff, no BasedPyright)

**Severity: Medium. Effort: S.**

Files: `.pre-commit-config.yaml:134-135` (comments only), full file

Evidence: Pre-commit hooks present: standard hooks, trufflehog, bandit, conventional-commit, validate-pyproject, check-github-workflows, qlty, interrogate, darglint. Lines 134-135 are comments listing "Ruff (linting + formatting)" and "BasedPyright (type checking)" but no actual `ruff` or `basedpyright`/`pyright` hook exists (grep finds only comment text and cache-dir excludes). CI enforces both (`ci.yml:97-101,145-149`). A developer committing locally gets no Ruff/type feedback; failures surface only in CI. Ruff/BasedPyright are routed through the `qlty` local hook instead, but qlty hooks are in the pre-commit.ci `skip` list (line 15), so on hosted pre-commit.ci they do not run at all.

Recommendation: Add the upstream `astral-sh/ruff-pre-commit` hook (check + format) and a BasedPyright hook, or document that qlty is the single source and confirm qlty actually runs Ruff in the commit path.

---

## CI-07 Redundant coverage destinations and duplicate Qlty caller

**Severity: Medium. Effort: M** (consolidate after deciding canonical tool).

Files: `ci.yml:200`; `codecov.yml`; `qlty.yml`; `coverage.yml`; `sonarcloud.yml`

Evidence: Coverage is shipped to three services: Codecov (inline `ci.yml:200` AND again via `codecov.yml` workflow_run caller), Qlty (`qlty.yml` + `coverage.yml`), and SonarCloud (`sonarcloud.yml`). `qlty.yml:18` and `coverage.yml:26` both call the same reusable workflow `python-qlty-coverage.yml@main` with the same `coverage-artifact-name` - two workflows doing the identical Qlty upload. Codecov is also uploaded twice (inline in CI plus the dedicated caller). This is duplicated minutes and duplicated PR comments.

Recommendation: Pick one coverage host. Remove `coverage.yml` (duplicate of `qlty.yml`) or `qlty.yml`. Drop either the inline `ci.yml:200` Codecov upload or the `codecov.yml` caller, not both paths.

---

## CI-08 Overlapping SAST scanners (CodeQL + SonarCloud + Qlty + Bandit + Semgrep + Scorecard + OSV)

**Severity: Low. Effort: M** (governance decision, not code).

Files: `codeql.yml`, `sonarcloud.yml`, `qlty.yml`, `ci.yml:179-181`, `.semgrep.yml`, `scorecard.yml`, `security-analysis.yml`, `osv-scanner.toml`, `dependency-review.yml`, `sbom.yml`, `slsa-provenance.yml`

Evidence: Seven+ overlapping analysis surfaces. Python SAST is covered by CodeQL, SonarCloud, Qlty (which wraps Ruff+Bandit), inline Bandit, and Semgrep - four tools flag the same class of issues. Dependency vulns covered by OSV (`osv-scanner.toml`), Safety, `dependency-review.yml`, and Renovate. For a small library this is high run-cost and review-noise for marginal added coverage. Most are scheduled weekly (`security-analysis` Mon 09:00, `codeql` Mon 07:00, `sbom` Mon 08:00, `scorecard` Tue) which stacks Monday-morning compute.

Recommendation: Keep CodeQL (free, GitHub-native, required for advanced security) + one of {SonarCloud, Qlty}. Drop the redundant one and the inline Bandit (Qlty already runs Bandit per `.qlty/qlty.toml:145`). Document the chosen stack.

---

## CI-09 Org reusable workflows pinned to mutable @main

**Severity: Medium. Effort: S.**

Files: 12 callers - `sbom.yml:38`, `slsa-provenance.yml:101`, `fips-compatibility.yml:55`, `mutation-testing.yml:43`, `qlty.yml:18`, `docs.yml:32`, `codecov.yml:26`, `security-analysis.yml:37`, `scorecard.yml:29`, `coverage.yml:26`, `reuse.yml:27`, `python-compatibility.yml:37`

Evidence: All external third-party actions are SHA-pinned (41/41), but 12 callers of `ByronWilliamsCPA/.github/.github/workflows/*.yml` use `@main`. Two callers already pin correctly to a SHA with a `# main` comment (`pr-validation.yml:32` and `sonarcloud.yml:35` -> `e8fc83c98c2971ad1ece71573d28171463e30c16`), proving the pattern is known and inconsistently applied. A push to the org `.github` default branch silently changes CI/release/SLSA behavior here. For supply-chain integrity this defeats SHA-pinning of the leaf actions, since the reusable workflow can swap them.

Recommendation: Pin all 12 to the same SHA (or per-workflow release tags) as the two that already are. Let Renovate bump them.

---

## CI-10 setup-uv version skew + mislabeled SHA comment

**Severity: Low. Effort: S.**

Files: all workflows using `astral-sh/setup-uv`

Evidence: Three labels for two SHAs:
- `38f3f104447c67c051c4a08e39b64a148898af3a` commented `# v4` (7 uses) and `# v4.2.0` (1 use, `codeql.yml:52`) - same SHA, two different version comments, so one comment is wrong.
- `d0cc045d04ccac9d8b7881df0226f9e82c39688e # v6.8.0` (1 use, `pr-validation.yml:67`).
Most workflows run setup-uv v4 while one runs v6.8.0. checkout has the same cosmetic issue: SHA `34e1148...` labeled both `# v4` (`publish-artifact-registry.yml:63`) and `# v4.3.1` (10 uses).

Recommendation: Normalize on one setup-uv major (v6) across all workflows; fix the mislabeled comments. Renovate will keep them aligned once consistent.

---

## CI-11 Path filters watch src/ while code lives in packages/

**Severity: Medium. Effort: S.**

Files: `fips-compatibility.yml:23,30`, `mutation-testing.yml:25`, `python-compatibility.yml:11,18`; `sonarcloud.yml:39`; `noxfile.py:415,429`; `pyproject.toml:712,723`

Evidence: This is a workspace with code under `packages/*/src/`. The root `src/python_libs` exists but the actively published code is in `packages/`. Several workflows trigger or scan only `src/`:
- `python-compatibility.yml` paths `src/**/*.py` and `source-directory: 'src'` (line) - never triggers on `packages/**` changes, so cross-version testing of the four packages never runs on a package-only PR.
- `fips-compatibility.yml:23,30` and `mutation-testing.yml:25` path-trigger on `src/**/*.py` only.
- `sonarcloud.yml:39` `source-directory: 'src'` - Sonar analyzes the wrong tree.
- noxfile `lint`/`typecheck` run `ruff check .` (ok) but `basedpyright src` (line 429) and Bandit `targets = ["src"]` (pyproject:712) and Vulture `paths = ["src/"]` (pyproject:723) all miss `packages/`.

Recommendation: Add `packages/**` to the path filters and point source-directory / scan targets at `packages` (or both). Confirm whether root `src/python_libs` is still shipped; if not, drop it to remove ambiguity.

---

## CI-12 Formatter width disagreements (low impact)

**Severity: Low. Effort: S.**

Files: `pyproject.toml:152`, `.prettierrc`, `.markdownlint.json`, `.yamllint:11`

Evidence: Widths are intentional-by-filetype but worth recording: Python 88 (Ruff `line-length = 88`, Prettier default `printWidth: 88`) - consistent. Markdown: CLAUDE.md says 120; Prettier MD `printWidth: 120` - but `.markdownlint.json` sets `"line-length": false` and `MD013: false`, so markdownlint does not enforce the 120 the standard claims; only Prettier reflows. YAML: Prettier `printWidth: 120` vs `.yamllint` `line-length.max: 150` (and `level: warning`) - a 100-char YAML line passes Prettier reflow target but yamllint only warns up to 150. No hard conflict (yamllint line-length is `warning`), but the three sources disagree on the YAML/MD ceiling.

Recommendation: Set `.yamllint` line-length max to 120 to match Prettier, and decide whether markdownlint should enforce MD013 at 120 rather than disabling it.

---

## Summary table

| ID | Title | Severity | Effort | Files |
|----|-------|----------|--------|-------|
| CI-01 | CI tests only 2 of 4 packages | Critical | M | ci.yml:32-156 |
| CI-02 | Coverage gate disabled in CI (--cov-fail-under=0) | High | S | ci.yml:94,142 |
| CI-03 | Coverage artifact name mismatch breaks uploads | High | S | ci.yml:107,155; codecov.yml:28; qlty.yml:23; coverage.yml:28 |
| CI-04 | Non-blocking Bandit (`\|\| true`) | High | S | ci.yml:181 |
| CI-05 | Python-version drift across 4 tool/matrix sets | Medium | M | pyproject.toml:12,153,502; noxfile.py:295; sonar-project.properties:22 |
| CI-06 | Pre-commit lacks Ruff/BasedPyright that CI runs | Medium | S | .pre-commit-config.yaml:134-135 |
| CI-07 | Redundant coverage uploads + duplicate Qlty caller | Medium | M | ci.yml:200; codecov.yml; qlty.yml; coverage.yml |
| CI-08 | Overlapping SAST scanners (7+) | Low | M | codeql/sonarcloud/qlty/ci.yml:181/.semgrep.yml/scorecard |
| CI-09 | Org reusable workflows pinned to @main | Medium | S | 12 callers (sbom.yml:38 etc.) |
| CI-10 | setup-uv version skew + mislabeled SHA comment | Low | S | all setup-uv callers |
| CI-11 | Path filters watch src/ while code is in packages/ | Medium | S | python-compatibility.yml:11; sonarcloud.yml:39; noxfile.py:429; pyproject.toml:712,723 |
| CI-12 | Formatter width disagreements (yaml/md) | Low | S | pyproject.toml:152; .prettierrc; .markdownlint.json; .yamllint:11 |
