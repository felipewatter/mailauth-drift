# Changelog

## v0.1.0 — Initial public release

- Python 3.11+ offline CLI to analyze policy snapshots without DNS or SMTP access.
- Directed SPF include/redirect dependency graph with cycle, depth, unresolved-reference, and conservative lookup-budget findings.
- Explicit DMARC RFC 9989 policy inspection, including new `t=` tag and historic `pct`, `ri`, `rf` warnings.
- Captured MTA-STS DNS+HTTPS policy cross-check and enforcement posture analysis.
- Deterministic JSON, text and SARIF 2.1.0 output; explainable SPF dependency tracing.
- Baseline-versus-candidate regression gate for SPF, DMARC and MTA-STS.
- Hardened file-size and input bounds, unit and CLI tests, reproducible release package and SHA-256 verification.
- Public release pipeline requires successful CI on `main` at the exact commit it packages.

**Caveat:** static analysis is heuristic. Findings are not proofs of exploitation, RFC-conformance certification, live DNS truth or mail deliverability.
