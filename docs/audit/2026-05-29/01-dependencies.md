# Dependencies and Supply Chain Audit

**Repository**: /home/user/python-libs
**Date**: 2026-05-29
**Scope**: Dependencies and supply chain only. Read-only audit.
**Auditor branch**: claude/repo-audit-KEOGN

## Method and tooling state

- `uv` 0.8.17 present. `pip-audit` is NOT installed in the project venv (`uv run pip-audit` fails:
  "Failed to spawn: pip-audit"). It is declared as a dev dependency (`pyproject.toml:92`) but the
  resolved environment did not have it on PATH. Audit ran via ephemeral `uvx pip-audit 2.10.0`.
- Vulnerability scan basis: `uv export --all-extras --no-hashes` to `/tmp/reqs-full.txt` (769 lines),
  then `pip-audit -r ... --no-deps`. The export and audit did not modify any tracked file.
- `uv.lock` is 601,500 bytes, lock format version 1 / revision 3, 238 `[[package]]` entries.
- Last commit touching `uv.lock`: 2d84e06 on 2025-12-15. Repo HEAD: c0eb24a on 2026-05-07.

## Summary of evidence counts

- pip-audit: 60 advisory rows across 30 distinct packages (full dev+prod set).
- Direct production deps that are vulnerable at locked versions: 3 (pyjwt, cryptography, starlette).
- Direct deps with no upstream release in 18+ months: 0 confirmed among production deps;
  1 dev-transitive package (`py`) abandoned since 2021.
- Migration residue files (requirements*.txt, setup.py, setup.cfg, poetry.lock, Pipfile): 0 anywhere
  (find across tree and `git ls-files` both empty).

---

## DEP-01: Vulnerable production cryptography/auth deps at locked versions

**Severity**: High
**Effort**: S (version bumps; basis: all fixes are patch/minor on already-pinned ranges, no API breaks expected)
**Files**: `packages/cloudflare-auth/pyproject.toml:29-31`, `packages/cloudflare-auth/pyproject.toml:38-45`, `uv.lock`

**Evidence** (pip-audit, locked versions from `uv.lock`):

| Package | Locked | Advisory | Fix |
|---|---|---|---|
| pyjwt | 2.10.1 | PYSEC-2026-120 | 2.12.0 |
| pyjwt | 2.10.1 | PYSEC-2025-183 | (no fix listed) |
| cryptography | 46.0.3 | CVE-2026-26007 | 46.0.5 |
| cryptography | 46.0.3 | PYSEC-2026-35 | 46.0.6 |
| cryptography | 46.0.3 | PYSEC-2026-36 | 46.0.7 |
| starlette | 0.50.0 | PYSEC-2026-161 | 1.0.1 |

pyjwt and cryptography are direct production dependencies of `cloudflare-auth` (a JWT validation /
auth middleware library). starlette is a direct dep under the `fastapi`/`all` extras. These are the
load-bearing security path of the package, so vulnerable JWT and crypto code is the worst place to
carry known advisories. The declared floors (`pyjwt>=2.8.0`, `cryptography>=41.0.0`,
`starlette>=0.27.0`) are wide open, so a fresh `uv lock` would pull the fixes; the stale lock (DEP-03)
is why they persist.

**Note**: the starlette fix is `1.0.1`, a major version jump from 0.50.0. Verify FastAPI compatibility
before bumping; FastAPI pins starlette ranges.

**Recommendation**: Re-resolve the lock and confirm pyjwt >= 2.12.0, cryptography >= 46.0.7,
starlette to a fixed line compatible with the pinned FastAPI. Run `uv run pip-audit` in CI (it is
declared but not actually invoked by any workflow that I can see in the SBOM caller).

**CVE**: PYSEC-2026-120, PYSEC-2025-183, CVE-2026-26007, PYSEC-2026-35, PYSEC-2026-36, PYSEC-2026-161.

---

## DEP-02: Large volume of vulnerable transitive and dev-tool dependencies

**Severity**: Medium
**Effort**: M (most are dev/docs tooling; bump in batches, basis: spread across jupyter/docs/safety chains needing per-tool compat checks)
**Files**: `uv.lock`, `pyproject.toml:79-132` (dev extra)

**Evidence**: Beyond DEP-01, pip-audit flagged these. Production-reachable transitive deps first:

| Package | Locked | Advisory | Fix | Reaches prod via |
|---|---|---|---|---|
| urllib3 | 2.5.0 | PYSEC-2026-141, CVE-2025-66418, CVE-2025-66471, CVE-2026-21441 | 2.7.0 / 2.6.x | google-*, httpx chain, requests |
| idna | 3.11 | CVE-2026-45409 | 3.15 | httpx / requests |
| requests | 2.32.5 | CVE-2026-25645 | 2.33.0 | google-* chain |
| protobuf | 6.33.1 | CVE-2026-0994 | 6.33.5 | google-cloud-storage, google-genai |
| pyasn1 | 0.6.1 | CVE-2026-23490, CVE-2026-30922 | 0.6.2 / 0.6.3 | google-auth (rsa/asn1) |

Dev/docs-only (not shipped to consumers of the packages):

authlib 1.6.5 (5 advisories, via `safety`), filelock 3.20.0 (2), gitpython 3.1.45 (4),
jupyter-server 2.17.0 (4), jupyterlab 4.5.0 (2), marshmallow 4.1.0 (1), mistune 3.1.4 (4),
nbconvert 7.16.6 (3), nltk 3.9.2 (7), notebook 7.5.0 (1), pip 25.3 (3), pygments 2.19.2
(CVE-2026-4539), pymdown-extensions 10.17.2 (CVE-2026-46338), pytest 9.0.1 (CVE-2025-71176),
python-dotenv 1.2.1 (CVE-2026-28684), tornado 6.5.2 (3), virtualenv 20.35.4 (CVE-2026-22702).

The production-reachable transitive set (urllib3, idna, requests, protobuf, pyasn1) matters most:
these ship in the resolved graph that downstream consumers inherit through the published packages.
The jupyter/nltk/safety cluster comes in only through the heavy `dev` extra in the root
`pyproject.toml` (jupyter, ipykernel, safety, mkdocs stack); it does not affect published wheels.

**Recommendation**: Re-resolve to pull fixed transitive versions (urllib3 >= 2.7.0, idna >= 3.15,
requests >= 2.33.0, protobuf >= 6.33.5, pyasn1 >= 0.6.3). For dev tooling, bump or accept per the
SBOM threshold; the SBOM workflow only fails on CRITICAL/HIGH (DEP-06), so these Mediums pass silently.

**CVE**: see table.

---

## DEP-03: Lockfile is stale relative to upstream; reproducible but out of date

**Severity**: High
**Effort**: S (single `uv lock` re-resolve plus test run; basis: open version floors mean low churn risk)
**Files**: `uv.lock`, `pyproject.toml`

**Evidence**: `uv.lock` was last modified by commit 2d84e06 on 2025-12-15; repo HEAD is 2026-05-07.
Resolved upstream artifacts carry late-2025 `upload-time` stamps (e.g. authlib 1.6.5 uploaded
2025-10-02 per `uv.lock:186`). That is roughly 5.5 months of drift versus the 2026-05-29 audit date,
and it is the direct cause of every 2026-dated CVE in DEP-01/DEP-02 still applying: the version floors
in the pyproject files are open (`>=`), so the fixes exist but were never re-resolved into the lock.

Positives: the lock is internally consistent (`requires-python = ">=3.10, <3.15"` matches all five
pyproject files), uses revision 3 with `resolution-markers` for the full 3.10-3.14 matrix, and pins
exact versions with hashes (verified hashes present on each package, e.g. `uv.lock:186-188`).
Reproducibility is sound; freshness is the problem.

**Recommendation**: Run `uv lock` (and `uv lock --upgrade` deliberately), commit, and re-audit.
Add a scheduled job that runs `uv lock --upgrade` and `pip-audit` so drift is caught; the SBOM
workflow is path-triggered on `uv.lock`/`pyproject.toml` changes (`sbom.yml:13-25`) and so does
nothing while the lock sits stale.

---

## DEP-04: Abandoned dev-transitive package `py` (1.11.0, last release 2021)

**Severity**: Low
**Effort**: S (drop or replace the consumer; basis: single transitive edge)
**Files**: `uv.lock` (`name = "py"` block), `osv-scanner.toml:51-78`

**Evidence**: `py` 1.11.0 resolved with `upload-time = "2021-11-04T17:17:01.377Z"` (`uv.lock`). That is
~4.5 years with no release: the package is unmaintained. pip-audit flags PYSEC-2022-42969 (the
disputed ReDoS). It enters only as a dev transitive (pulled by the interrogate/test tooling chain).
This is already acknowledged: `osv-scanner.toml:54-78` ignores CVE-2022-42969 / PYSEC-2022-42969 /
GHSA-w596-4wvx-j9j6 with a reason that it is a dev-only, disputed, SVN-path-parsing issue.

This is the only dependency in the graph that crosses the 18-month-no-release line. No production
direct dependency is stale: the five pyproject files declare actively maintained libraries
(pydantic 2.12.5, httpx 0.28.1, cloudflare 4.3.1, google-cloud-storage 3.6.0, google-genai 1.55.0,
redis 7.1.0, structlog 25.5.0, rich 14.2.0), all resolved to 2025 releases.

**Recommendation**: Keep the documented exception. Optionally pin the consuming dev tool to a version
that has dropped `py`, or accept since it is dev-only and disputed. No production exposure.

**CVE**: CVE-2022-42969 / PYSEC-2022-42969 (disputed, already excepted).

---

## DEP-05: Python version policy is inconsistent across config, CI, and runtime claims

**Severity**: Medium
**Effort**: M (decide policy, then update classifiers/CI matrix/CLAUDE.md; basis: spans several files plus a 3.14 test matrix add)
**Files**: all five `pyproject.toml:12` (`requires-python = ">=3.10,<3.15"`), `pyproject.toml:153`
(`target-version = "py312"`), `pyproject.toml:502` (`pythonVersion = "3.12"`), `.github/workflows/ci.yml:71,119`,
`CLAUDE.md`

**Evidence**: Three different version stories coexist:

- `requires-python = ">=3.10,<3.15"` in all five pyprojects, and the lock carries 3.10-3.14
  resolution markers. So the declared support ceiling is 3.14.
- CI test matrices run `['3.10', '3.11', '3.12', '3.13']` (`ci.yml:71`, `:119`). Python 3.14 is
  claimed-supported and resolved in the lock but never tested. Trove classifiers in the package
  pyprojects also stop at 3.13 (e.g. `cloudflare-auth/pyproject.toml:17-20`).
- CLAUDE.md states "Python: 3.12" as the stack, and both Ruff (`target-version = "py312"`) and
  BasedPyright (`pythonVersion = "3.12"`) are pinned to 3.12, so lint/type analysis does not validate
  the 3.10 floor or the 3.13/3.14 ceiling.

Floor risk: Python 3.10 reaches EOL in October 2026 (~5 months out). Shipping a 3.10 floor now means
a known-soon-dead runtime in the support contract. The `UP017` ruff rule is disabled specifically for
3.10 (`pyproject.toml:268`) and backports (tomli, exceptiongroup, typing-extensions) are present in
the lock under `python_version < '3.11'` markers, so 3.10 support carries real maintenance weight.

**Recommendation**: Pick one policy. If 3.14 is supported, add it to the CI matrix and classifiers.
If not, lower `requires-python` to `<3.14`. Plan to drop the 3.10 floor at or before its Oct-2026 EOL.
Align CLAUDE.md ("3.12") with the actual `>=3.10` support range, or narrow the range.

---

## DEP-06: SBOM/scan delegated to external reusable workflow; thresholds and triggers leave gaps

**Severity**: Low
**Effort**: S (tighten threshold and add scheduled re-resolve; basis: config-only edits)
**Files**: `.github/workflows/sbom.yml:36-44`, `osv-scanner.toml`, `pyproject.toml:92`

**Evidence**: SBOM and scanning are delegated to an org-level reusable workflow
`ByronWilliamsCPA/.github/.github/workflows/python-sbom.yml@main` (`sbom.yml:38`). Observations:

- The caller pins the reusable workflow by branch (`@main`), not a SHA/tag. Every other action in the
  repo is SHA-pinned (e.g. `actions/checkout@34e1148...` in `ci.yml`), so this is the one unpinned,
  mutable supply-chain edge in CI. A compromised or changed `@main` runs with `security-events: write`.
- `severity-threshold: 'CRITICAL,HIGH'` and `fail-on-vulnerabilities: true` (`sbom.yml:41-42`): the
  ~25 Medium-rated advisories in DEP-02 will not fail the build. `fail-on-forbidden-licenses: false`
  means license findings never block.
- Trigger is path-filtered on `pyproject.toml`/`uv.lock` changes plus a weekly Monday cron
  (`sbom.yml:13-28`). The weekly cron does catch newly disclosed CVEs against the existing lock, which
  partly mitigates DEP-03; but nothing re-resolves the lock, so the scan reports findings it cannot fix.
- `pip-audit` is a declared dev dep (`pyproject.toml:92`) but I found no workflow that runs it; the SBOM
  workflow uses Trivy. So local `uv run pip-audit` and the documented `safety check` are not part of CI
  evidence as far as the workflow files show.
- SBOM accuracy itself is sound in principle: it builds CycloneDX from the uv graph and the lock is
  complete (238 packages, hashes present), so the SBOM will reflect the resolved tree accurately. The
  gap is that the resolved tree is stale (DEP-03), so the SBOM is an accurate picture of an outdated graph.

**Recommendation**: Pin the reusable workflow to a commit SHA or release tag. Lower the fail threshold
to include MEDIUM (or document why not). Add a scheduled lock-refresh + `pip-audit`/`safety` gate so the
weekly scan acts on a current graph instead of reporting unfixable stale findings.

---

## DEP-07: No migration residue (confirming finding)

**Severity**: Low
**Effort**: S
**Files**: tree-wide

**Evidence**: `find` across the tree (excluding `.venv`) and `git ls-files` filtered for
`requirements*.txt`, `setup.py`, `setup.cfg`, `poetry.lock`, `Pipfile*` both returned nothing. The repo
is cleanly on PEP 621 + uv with no leftover tooling. `scripts/generate_requirements.sh` exists and
*generates* `requirements.txt` / `requirements-dev.txt` on demand from `uv.lock` via `uv export`
(`generate_requirements.sh:72-86`), but it does not commit them and none are tracked. The script's
`--no-hashes` option weakens install integrity if used; default keeps hashes
(`generate_requirements.sh:31,66-70`). No action required beyond awareness that generated
requirements files, if produced, would bypass the lock's hash pinning when `--no-hashes` is passed.

---

## Findings table

| ID | Title | Severity | Effort | Files |
|---|---|---|---|---|
| DEP-01 | Vulnerable production crypto/auth deps at locked versions | High | S | cloudflare-auth/pyproject.toml, uv.lock |
| DEP-02 | Vulnerable transitive and dev-tool dependencies (60 rows / 30 pkgs) | Medium | M | uv.lock, pyproject.toml |
| DEP-03 | Stale lockfile (~5.5 months); reproducible but out of date | High | S | uv.lock, pyproject.toml |
| DEP-04 | Abandoned dev-transitive package `py` (2021) | Low | S | uv.lock, osv-scanner.toml |
| DEP-05 | Inconsistent Python version policy; 3.10 EOL Oct 2026; 3.14 untested | Medium | M | all pyproject.toml, ci.yml, CLAUDE.md |
| DEP-06 | SBOM workflow unpinned `@main`, MEDIUM not gated, no pip-audit in CI | Low | S | sbom.yml, osv-scanner.toml |
| DEP-07 | No migration residue (confirming) | Low | S | tree-wide |
