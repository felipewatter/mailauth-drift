# Security Policy

## Scope

MailAuth Drift inspects **local, user-supplied JSON snapshots only**. It never queries live DNS, authenticates to cloud accounts or contacts mail servers. No email message processing or message-level SPF/DMARC validation is performed.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.1.x | Supported |

## Responsible disclosure

Please report potentially exploitable parser issues or unsafe behavior using GitHub's **Security → Report a vulnerability** private advisory flow. Do not publish payloads containing real credentials, private DNS zone exports, or internal customer information in public issues.

We assess reports and publish fixes as appropriate; no specific response-time guarantee is made.

## Threat model summary

- **Adversarial inputs:** untrusted snapshot JSON, TXT strings, DNS names, malformed SPF references, very large files, unusual Unicode.
- **Controls:** file and object bounds, strict input schema, bounded graph recursion, read-only analysis, no subprocess calls in the scanner, escaped JSON/SARIF formatting, and refusal to write reports through symlinks.
- **Out of scope:** DNS spoofing protection, verifying origin or authenticity of captured snapshots, checking remote TLS certificates, canonical DMARC tree-walk resolution, SPF runtime matching, DKIM signature validation, runtime network exploration, guaranteed compliance outcomes.
- **Trust boundary:** the snapshot's content is trusted as an *assertion about a DNS state*, not a verified DNS observation. Control snapshot provenance independently.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
