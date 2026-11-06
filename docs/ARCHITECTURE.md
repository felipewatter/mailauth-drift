# Architecture

```text
                 user-provided versioned DNS snapshots
                              |
                              v
                        Bounded JSON loader
                              |
                              v
                 Name normalization + schema validation
                              |
              +---------------+---------------+
              |               |               |
        SPF graph walker   DMARC tags     MTA-STS pair
              |               |               |
              +---------------+---------------+
                              |
                        domain statuses
                              |
                    +---------+---------+
                    |                   |
               rule findings       policy diff
                    |                   |
              text/JSON/SARIF      text/JSON CI gate
```

The snapshot loader accepts the documented JSON schema only; no YAML or remote queries. A full file is bounded to 2 MiB, with limits on domains, TXT keys, record lengths, number of records and graph depth.

**SPF graph:** for each declared domain the analyzer follows `include:` and `redirect=` references present in its TXT map. It detects cycles, unresolved references and a conservative maximum lookup-path estimate. This is not an SPF `check_host()` engine; actual lookups vary with message inputs, macro expansion, MX/PTR results and early matches.

**DMARC:** checks explicitly captured policy for each monitored owner `_dmarc.<domain>`. It does not perform RFC 9989 organizational-domain tree walks or public-suffix resolution. `sp` and `np` are treated as declared/defaulted tags for policy comparison, **not** actual policy evaluations on subdomains. `p=reject` should not automatically be recommended for general-purpose domains; rollout decisions require operational context.

**MTA-STS:** DNS `_mta-sts` TXT and captured HTTPS policy are supplied independently. Their existence and syntax are checked, but DNS id synchronization and HTTPS/TLS retrieval, trust, MX certificate matching and HTTPS policy authenticity are not validated.

**Diff:** candidate policy fields are compared against baseline. A relaxation is flagged as a *review-required regression*, not as an automatically exploitable vulnerability. Regression severity is a prioritization heuristic.

**Reports:** stable JSON ordering and no timestamps avoid non-deterministic outputs. SARIF location points to `snapshot.json` as a logical source because JSON input may aggregate data from many DNS origins.
