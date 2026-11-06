"""SPF graph, DMARC RFC9989 policy, and MTA-STS posture heuristics.

No live DNS requests; no full SPF check_host(), DMARC alignment or SMTP TLS simulation.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Any

from .snapshot import DomainSnapshot, Snapshot, SnapshotError, name

SEVERITIES = ("info", "low", "medium", "high", "critical")
_LOOKUP = {"include", "a", "mx", "ptr", "exists", "redirect"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    domain: str
    location: str
    message: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _finding(out: list[Finding], rule: str, severity: str, domain: str,
             location: str, message: str, evidence: tuple[str, ...] = ()) -> None:
    out.append(Finding(rule, severity, domain, location, message, evidence))


def _records(txt: dict[str, tuple[str, ...]], owner: str, prefix: str) -> list[str]:
    return [v for v in txt.get(owner, ()) if v.lower().split(maxsplit=1)[0] == prefix.lower()]


def _spf_tokens(record: str) -> list[str]:
    return record.strip().split()[1:]


def _spf_verb(token: str) -> tuple[str, str, str]:
    qualifier = token[0] if token.startswith(("+", "-", "~", "?")) else "+"
    value = token[1:] if token.startswith(("+", "-", "~", "?")) else token
    if "=" in value:
        mechanism, argument = value.split("=", 1)
    elif ":" in value:
        mechanism, argument = value.split(":", 1)
    else:
        mechanism, argument = value.split("/", 1)[0], ""
    return qualifier, mechanism.lower(), argument


def _spf_graph(cfg: DomainSnapshot, out: list[Finding]) -> dict[str, Any]:
    root = cfg.domain
    edges: list[dict[str, str]] = []
    paths: list[list[str]] = []
    max_lookups = 0
    incomplete = False
    active: set[str] = set()
    seen: set[tuple[str, str]] = set()
    root_terminal: str | None = None
    root_redirect: str | None = None
    root_valid = True

    def visit(domain: str, path: tuple[str, ...], lookup_count: int) -> int:
        nonlocal max_lookups, incomplete, root_terminal, root_redirect, root_valid
        if len(path) > 20:
            incomplete = True
            _finding(out, "MAD-SPF-DEPTH", "high", root, domain, "SPF graph exceeds depth 20", path)
            return lookup_count
        if domain in active:
            incomplete = True
            _finding(out, "MAD-SPF-CYCLE", "high", root, domain, "Recursive SPF include/redirect cycle", path + (domain,))
            return lookup_count
        active.add(domain)
        current = path + (domain,)
        recs = _records(cfg.txt, domain, "v=spf1")
        if not recs:
            incomplete = True
            if domain == root:
                root_valid = False
                _finding(out, "MAD-SPF-MISSING", "high", root, domain, "No SPF TXT record in snapshot")
            else:
                _finding(out, "MAD-SPF-REF", "high", root, domain, "Included/redirected SPF target absent from snapshot", current)
            active.remove(domain)
            return lookup_count
        if len(recs) != 1:
            incomplete = True
            root_valid = False if domain == root else root_valid
            _finding(out, "MAD-SPF-MULTIPLE", "high", root, domain, "Multiple SPF records at owner name", current)
            active.remove(domain)
            return lookup_count
        tokens = _spf_tokens(recs[0])
        all_tokens = []
        redirect_tokens = []
        branch_count = lookup_count
        for i, raw in enumerate(tokens):
            qual, mechanism, arg = _spf_verb(raw)
            if mechanism == "all":
                if raw.lstrip("+-~?") != "all":
                    _finding(out, "MAD-SPF-SYNTAX", "high", root, domain, "Malformed all mechanism", current)
                all_tokens.append((i, qual))
            if mechanism == "redirect":
                redirect_tokens.append(arg)
            if mechanism == "ptr":
                _finding(out, "MAD-SPF-PTR", "medium", root, domain, "PTR mechanism discouraged by RFC 7208", current)
            if mechanism in {"ip4", "ip6"}:
                try:
                    net = ipaddress.ip_network(arg, strict=False)
                    if net.version != (4 if mechanism == "ip4" else 6):
                        raise ValueError("address family mismatch")
                except ValueError:
                    _finding(out, "MAD-SPF-SYNTAX", "high", root, domain, f"Invalid {mechanism} address", current)
            if mechanism not in _LOOKUP | {"all", "ip4", "ip6", "exp"}:
                _finding(out, "MAD-SPF-SYNTAX", "high", root, domain, f"Unrecognized SPF term {mechanism}", current)
            if mechanism in _LOOKUP:
                branch_count += 1
                max_lookups = max(max_lookups, branch_count)
                if mechanism in {"include", "redirect"}:
                    if not arg or "%{" in arg or "%" in arg:
                        incomplete = True
                        _finding(out, "MAD-SPF-DYNAMIC", "medium", root, domain, "Dynamic or empty SPF reference cannot be resolved offline", current)
                        continue
                    try:
                        target = name(arg)
                    except SnapshotError:
                        _finding(out, "MAD-SPF-SYNTAX", "high", root, domain, "Malformed SPF reference", current)
                        continue
                    edges.append({"from": domain, "to": target, "mechanism": mechanism})
                    seen.add((domain, target))
                    paths.append(list(current + (target,)))
                    # The maximum path is a conservative static estimate, not a runtime SPF result.
                    branch_count = max(branch_count, visit(target, current, branch_count))
                if mechanism in {"a", "mx", "ptr", "exists"} and "%{" in raw:
                    incomplete = True
        if all_tokens:
            if len(all_tokens) != 1 or all_tokens[-1][0] != len(tokens) - 1:
                _finding(out, "MAD-SPF-TERMINATOR", "medium", root, domain, "all must occur once at end of SPF policy", current)
            if domain == root:
                root_terminal = {"-": "fail", "~": "softfail", "?": "neutral", "+": "pass"}[all_tokens[-1][1]]
            if all_tokens[-1][1] == "+":
                _finding(out, "MAD-SPF-ALLOWALL", "critical", root, domain, "SPF +all authorizes every sender", current)
        if redirect_tokens:
            if len(redirect_tokens) > 1:
                _finding(out, "MAD-SPF-REDIRECT", "high", root, domain, "Multiple redirect modifiers", current)
            if domain == root:
                root_redirect = redirect_tokens[0]
            if all_tokens:
                _finding(out, "MAD-SPF-REDIRECT", "medium", root, domain, "redirect is ignored when all mechanism matches", current)
        if not all_tokens and not redirect_tokens:
            _finding(out, "MAD-SPF-NEUTRAL", "medium", root, domain, "SPF has implicit neutral default", current)
        active.remove(domain)
        return branch_count

    visit(root, (), 0)
    if max_lookups > 10:
        _finding(out, "MAD-SPF-LOOKUPS", "high", root, root, f"Conservative SPF lookup path estimate is {max_lookups} (>10)")
    if root_terminal in ("pass", "neutral", "softfail"):
        level = {"pass": "critical", "neutral": "medium", "softfail": "low"}[root_terminal]
        _finding(out, "MAD-SPF-WEAK", level, root, root, f"Root SPF terminal policy: {root_terminal}")
    if root_terminal is None and root_redirect is not None:
        root_terminal = "redirected"
    return {"terminal": root_terminal or "missing", "root_valid": root_valid,
            "max_lookup_path_estimate": max_lookups, "incomplete": incomplete,
            "edges": sorted(edges, key=lambda x: (x["from"], x["to"], x["mechanism"])),
            "paths": sorted(paths), "reference_count": len(seen)}


def _parse_tag_value(value: str, marker: str, required: tuple[str, ...]) -> tuple[dict[str, str], bool]:
    chunks = [s.strip() for s in value.split(";") if s.strip()]
    if not chunks or chunks[0] != marker:
        return {}, False
    result: dict[str, str] = {"v": marker.split("=", 1)[1]}
    for chunk in chunks[1:]:
        if "=" not in chunk:
            return result, False
        k, v = (x.strip() for x in chunk.split("=", 1))
        if not re.fullmatch(r"[a-z][a-z0-9]*", k) or k in result or not v:
            return result, False
        result[k] = v
    return result, all(k in result for k in required)


def _dmarc(cfg: DomainSnapshot, out: list[Finding]) -> dict[str, Any]:
    domain = cfg.domain
    owner = f"_dmarc.{domain}"
    # Match only the exact DMARC version, with optional trailing semicolon.
    records = [r for r in cfg.txt.get(owner, ()) if re.match(r"^v=DMARC1(?:\s*;|\s*$)", r)]
    if not records:
        _finding(out, "MAD-DMARC-MISSING", "high", domain, owner, "No explicit DMARC policy in snapshot; inherited policy not modeled")
        return {"p": "missing", "sp": "missing", "np": "missing", "t": "n", "valid": False}
    if len(records) > 1:
        _finding(out, "MAD-DMARC-MULTIPLE", "high", domain, owner, "Multiple DMARC TXT records at owner name")
        return {"p": "invalid", "sp": "invalid", "np": "invalid", "t": "n", "valid": False}
    tags, valid = _parse_tag_value(records[0], "v=DMARC1", ("p",))
    if not valid:
        _finding(out, "MAD-DMARC-SYNTAX", "high", domain, owner, "Malformed DMARC policy or missing p tag")
    for key in ("p", "sp", "np"):
        if key in tags and tags[key] not in {"none", "quarantine", "reject"}:
            valid = False
            _finding(out, "MAD-DMARC-SYNTAX", "high", domain, owner, f"Invalid {key} policy")
    for key in ("adkim", "aspf"):
        if key in tags and tags[key] not in {"r", "s"}:
            valid = False
            _finding(out, "MAD-DMARC-SYNTAX", "high", domain, owner, f"Invalid {key} alignment")
    if tags.get("t", "n") not in {"n", "y"}:
        valid = False
        _finding(out, "MAD-DMARC-SYNTAX", "high", domain, owner, "Invalid t= mode")
    if tags.get("psd", "n") not in {"y", "n"}:
        valid = False
        _finding(out, "MAD-DMARC-SYNTAX", "high", domain, owner, "Invalid psd tag")
    for obsolete in ("pct", "rf", "ri"):
        if obsolete in tags:
            _finding(out, "MAD-DMARC-HISTORIC", "medium", domain, owner,
                     f"Historic {obsolete} DMARC tag (RFC 9989); review migration")
    if valid and tags["p"] == "none":
        _finding(out, "MAD-DMARC-MONITOR", "medium", domain, owner, "DMARC explicitly in monitoring mode (p=none)")
    if valid and tags.get("t") == "y":
        _finding(out, "MAD-DMARC-TEST", "low", domain, owner, "DMARC testing t=y; evaluate before promotion")
    if valid and "rua" not in tags:
        _finding(out, "MAD-DMARC-REPORT", "low", domain, owner, "No aggregate reporting rua URI")
    return {"p": tags.get("p", "invalid"), "sp": tags.get("sp", tags.get("p", "invalid")),
            "np": tags.get("np", tags.get("sp", tags.get("p", "invalid"))),
            "t": tags.get("t", "n"), "adkim": tags.get("adkim", "r"),
            "aspf": tags.get("aspf", "r"), "valid": valid, "historic": sorted(set(tags) & {"pct", "rf", "ri"})}


def _mta_sts(cfg: DomainSnapshot, out: list[Finding]) -> dict[str, Any]:
    domain = cfg.domain
    owner = f"_mta-sts.{domain}"
    records = [r for r in cfg.txt.get(owner, ()) if r.startswith("v=STSv1;")]
    policy = cfg.mta_sts_policy
    if not records and policy is None:
        _finding(out, "MAD-STS-MISSING", "low", domain, owner, "No MTA-STS DNS record or captured HTTPS policy")
        return {"mode": "missing", "valid": False}
    dns_valid = len(records) == 1
    if not dns_valid:
        _finding(out, "MAD-STS-DNS", "medium", domain, owner, "MTA-STS DNS TXT record must be unique and present")
    else:
        parts, dns_valid = _parse_tag_value(records[0], "v=STSv1", ("id",))
        if not dns_valid or not parts.get("id"):
            _finding(out, "MAD-STS-DNS", "medium", domain, owner, "Invalid MTA-STS DNS id tag")
    if policy is None:
        _finding(out, "MAD-STS-POLICY", "medium", domain, owner, "No captured HTTPS MTA-STS policy; cannot verify mode")
        return {"mode": "unknown", "valid": False}
    mode = policy["mode"]
    policy_valid = policy["version"] == "STSv1" and mode in {"enforce", "testing", "none"}
    if mode != "none" and (not policy["mx"] or not policy["max_age"]):
        policy_valid = False
    if not policy_valid:
        _finding(out, "MAD-STS-POLICY", "high", domain, owner, "Invalid captured MTA-STS policy")
    valid = dns_valid and policy_valid
    if mode == "none":
        _finding(out, "MAD-STS-OFF", "medium", domain, owner, "MTA-STS is disabled (mode: none)")
    elif mode == "testing":
        _finding(out, "MAD-STS-TEST", "low", domain, owner, "MTA-STS testing mode; no transport enforcement requested")
    return {"mode": mode, "valid": valid, "max_age": policy["max_age"],
            "mx": sorted(set(policy["mx"]))}


def scan(snapshot: Snapshot) -> dict[str, Any]:
    findings: list[Finding] = []
    statuses: dict[str, Any] = {}
    for domain, cfg in sorted(snapshot.domains.items()):
        spf = _spf_graph(cfg, findings)
        dmarc = _dmarc(cfg, findings)
        sts = _mta_sts(cfg, findings)
        statuses[domain] = {"spf": spf, "dmarc": dmarc, "mta_sts": sts}
    findings.sort(key=lambda f: (f.domain, f.rule_id, f.location, f.message, f.evidence))
    return {"tool": "mailauth-drift", "schema_version": 1, "domains": statuses,
            "findings": [f.to_dict() for f in findings], "counts": {
                sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITIES}}
