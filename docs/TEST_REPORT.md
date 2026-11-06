# Local Validation Report — MailAuth Drift v0.1.0

**Scope:** Local validation only. GitHub Actions across Python 3.11/3.12/3.13 will be validated after the user creates the repository and approves publishing. A public release must **not** be represented as existing until verified on GitHub.

## Local checks

| Check | Result |
| --- | --- |
| Pytest unit + CLI + malicious input + packaging tests | **100 passed** |
| Runtime source coverage (pytest-cov, Python 3.13) | **95%** |
| Python compilation (`compileall`) | Pass |
| Trusted example `scan --fail-on high` | Pass, exit 0 |
| Intentionally weakened example `scan --format sarif --fail-on none` | Pass, SARIF 2.1.0 generated |
| Baseline-versus-candidate `diff --fail-on-regression` | Pass, expected exit 1 |
| SPF dependency `trace` | Pass |
| Invalid input | Pass, expected exit 2 |
| ZIP deterministic SHA-256 | Pass |
| ZIP CRC, Zip Slip and sensitive extensions | Pass |
| Action syntax and pinned checkout/setup-python | Inspected locally |
| Ruff | **Pending remote CI** (not available locally) |
| Wheel/sdist build | **Pending remote CI** (build module not installed locally) |
| GitHub Actions (3.11/3.12/3.13) | **Pending repository creation** |
| Official GitHub Release v0.1.0 | **Pending CI approval** |

### Local build environment

- Python 3.13.5
- Pytest and pytest-cov available
- Runtime Python package uses only Python standard library
- Ruff and `python -m build` unavailable locally because the package index was inaccessible. Both are installed and run in the GitHub Actions workflow.

## Verification principle

Never treat a security check as passed by merely creating its workflow definition. The actual remote CI status, job logs and release assets must be inspected after publishing. Release workflow revalidates the commit SHA before creating the version tag.
