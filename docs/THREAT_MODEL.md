# Threat Model and Explicit Boundaries

## Security goals

1. Make changes to **declared** DNS-based email authentication posture visible before deployment.
2. Keep secret-bearing infrastructure access out of the tool: **zero network operations**, no cloud credentials, no live mail ingestion.
3. Exit nonzero for parsed data errors or policy regressions in CI.
4. Preserve reproducible evidence for peer review without embedding raw email or signed messages.

## Trust assumptions

- Input JSON is a **captured/constructed assertion** about DNS TXT and MTA-STS policy, not verified truth.
- The reviewer chooses an appropriate baseline and controls who can change both baseline and candidate.
- A malicious author may remove a monitored domain or omit DNS references: removed domains produce a review-required change, missing included records produce a finding.
- A malicious actor who can alter both snapshots can evade drift detection; use protected branches and independently authenticated snapshots.

## Protections

| Risk | Control |
| --- | --- |
| Large file or record explosion | 2 MiB, 128 monitored domains, 2048 TXT names, 4096 records, 4096 chars/value |
| Cyclic SPF include/redirect graph | active recursion guard and depth 20 |
| DNS/SMTP exfiltration | no network dependencies or remote lookups |
| TXT injection into shell | records parsed as inert text; no subprocess or eval |
| Malicious Unicode labels | IDNA conversion and label validation |
| Report redirection through symlink | refuse a symlink output path |
| Unsupported JSON structures | strict top-level schema; fail with exit 2 |
| Untrusted GitHub PR content | read-only CI token, no privileged pull_request_target job |
| Privileged release path | only successful push-to-main CI on same repo and same commit; no downloaded artifacts from PR |

## Limitations / non-goals

- No receiver behavior or deliverability prediction; receivers make local policy decisions.
- No canonical SPF query budget: branch estimate may exceed what a real message evaluates, and DNS MX/PTR expansion can incur extra lookups not represented.
- No DKIM cryptographic checks, DNSSEC validation, DMARC tree walk, dynamic macros, Public Suffix List or DNS cache behavior.
- No ability to verify the captured MTA-STS HTTPS endpoint's ownership or actual TLS certificate.
- No absolute guarantee that all unsafe DNS changes are found.

See `docs/SEMANTICS.md` for rule-level descriptions.
