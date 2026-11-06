# Findings and Policy Comparison Semantics

| Rule | Severity | Meaning |
| --- | --- | --- |
| MAD-SPF-MISSING | High | Monitored root domain lacks explicit SPF in snapshot |
| MAD-SPF-MULTIPLE | High | Multiple competing SPF TXT records at owner |
| MAD-SPF-CYCLE | High | SPF include/redirect reference cycle |
| MAD-SPF-DEPTH | High | Recursive graph exceeds depth guard |
| MAD-SPF-REF | High | Referenced target not present in captured TXT map |
| MAD-SPF-LOOKUPS | High | Conservative term-count path exceeds 10; not conformance proof |
| MAD-SPF-ALLOWALL | Critical | Individual SPF record has `+all` |
| MAD-SPF-WEAK | Low / Medium / Critical | Weak root terminal SPF policy |
| MAD-SPF-PTR | Medium | Use of discouraged `ptr` mechanism |
| MAD-SPF-SYNTAX | High | Unsupported or malformed parsed SPF term |
| MAD-SPF-REDIRECT | Medium / High | Redirect misconfiguration signals |
| MAD-SPF-DYNAMIC | Medium | Dynamic macro/empty reference cannot be resolved offline |
| MAD-SPF-TERMINATOR | Medium | all not at final position or duplicated |
| MAD-SPF-NEUTRAL | Medium | No terminal all or redirect (implicit neutral) |
| MAD-DMARC-MISSING | High | No explicit DMARC record for monitored domain |
| MAD-DMARC-MULTIPLE | High | Multiple DMARC TXT records |
| MAD-DMARC-SYNTAX | High | Missing/duplicate/invalid required or known-value tag |
| MAD-DMARC-HISTORIC | Medium | Historic `pct`, `ri`, `rf` from RFC 7489 (removed in RFC 9989) |
| MAD-DMARC-MONITOR | Medium | Explicit DMARC p=none (monitoring, not enforcement) |
| MAD-DMARC-TEST | Low | `t=y` testing mode request |
| MAD-DMARC-REPORT | Low | No rua aggregate report URI |
| MAD-STS-MISSING | Low | Neither MTA-STS TXT nor captured HTTPS policy in snapshot |
| MAD-STS-DNS | Medium | MTA-STS DNS TXT absent/invalid/duplicated |
| MAD-STS-POLICY | Medium / High | Captured HTTPS policy unavailable or invalid |
| MAD-STS-OFF | Medium | MTA-STS mode=none |
| MAD-STS-TEST | Low | MTA-STS mode=testing |

## Exit codes

- `0`: successful evaluation and no matching blocking condition.
- `1`: security gate triggered (threshold in scan or `--fail-on-regression` in diff).
- `2`: invalid input or operational error; no partial pass.

## Diff rules

- DMARC `p`, `sp`, `np` moving toward `none` is marked *high*. This is a policy-relaxation indicator, **not** an instruction to enforce reject or a vulnerability finding.
- Alignment `s` -> `r` is marked *medium*. `t=n` -> `t=y` is *low*.
- SPF root `-all` -> `~all`/`?all`/`+all` is *high*. SPF lookups estimated above 10 and increased are *medium*.
- MTA-STS enforce -> testing/none/missing is *high*, reducing max_age is *low*, changing accepted MX patterns is *medium*.
- The set of monitored domains is part of the security baseline; removing a domain is *high*.
- New domains are *info* but their own findings appear in candidate_findings. `--fail-on-regression` does **not** automatically gate all findings on new domains; run `scan` as well.
- Defaulted DMARC `sp/np` are compared as declared/defaulted fields only. No actual DMARC DNS tree walk is modeled.

## References

- RFC 7208: https://www.rfc-editor.org/rfc/rfc7208
- RFC 9989 (obsoletes RFC 7489): https://www.rfc-editor.org/rfc/rfc9989
- RFC 8461 MTA-STS: https://www.rfc-editor.org/rfc/rfc8461
- RFC 8460 SMTP TLS reporting: https://www.rfc-editor.org/rfc/rfc8460
