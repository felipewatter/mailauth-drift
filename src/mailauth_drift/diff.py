"""Regression detection with explicit field-by-field policy comparisons."""

from __future__ import annotations

from typing import Any

from .scanner import scan
from .snapshot import Snapshot

_STRENGTH = {"missing": -1, "invalid": -1, "none": 0, "quarantine": 1, "reject": 2}
_SPF = {"missing": -2, "pass": -1, "neutral": 0, "softfail": 1, "redirected": 1, "fail": 2}
_STS = {"missing": -1, "unknown": -1, "none": 0, "testing": 1, "enforce": 2}


def compare(baseline: Snapshot, candidate: Snapshot) -> dict[str, Any]:
    before, after = scan(baseline), scan(candidate)
    changes: list[dict[str, Any]] = []

    def change(domain: str, field: str, old: Any, new: Any, severity: str, why: str) -> None:
        changes.append({"domain": domain, "field": field, "before": old, "after": new,
                        "severity": severity, "message": why})

    old_domains, new_domains = before["domains"], after["domains"]
    for domain in sorted(set(old_domains) | set(new_domains)):
        if domain not in new_domains:
            change(domain, "domain", "present", "removed", "high", "A monitored domain disappeared from candidate snapshot")
            continue
        if domain not in old_domains:
            change(domain, "domain", "absent", "present", "info", "New monitored domain added; review its findings")
            continue
        old, new = old_domains[domain], new_domains[domain]
        for k in ("p", "sp", "np"):
            old_v, new_v = old["dmarc"].get(k), new["dmarc"].get(k)
            if old_v != new_v:
                weakens = _STRENGTH.get(new_v, -1) < _STRENGTH.get(old_v, -1)
                change(domain, f"dmarc.{k}", old_v, new_v,
                       "high" if weakens else "info", "DMARC requested policy relaxed" if weakens else "DMARC requested policy changed (review deliverability)")
        for k in ("adkim", "aspf"):
            a, b = old["dmarc"].get(k), new["dmarc"].get(k)
            if a != b and a is not None and b is not None:
                change(domain, f"dmarc.{k}", a, b, "medium" if a == "s" and b == "r" else "info",
                       "DMARC identifier alignment changed")
        for k in ("valid", "t"):
            a, b = old["dmarc"].get(k), new["dmarc"].get(k)
            if a != b:
                severity = "high" if k == "valid" and a and not b else "low" if k == "t" and b == "y" else "info"
                change(domain, f"dmarc.{k}", a, b, severity, "DMARC validation/test status changed")
        for k in ("terminal", "root_valid"):
            a, b = old["spf"].get(k), new["spf"].get(k)
            if a != b:
                weakens = _SPF.get(b, -2) < _SPF.get(a, -2) if k == "terminal" else a and not b
                change(domain, f"spf.{k}", a, b, "high" if weakens else "info", "SPF root policy changed")
        a, b = old["spf"]["max_lookup_path_estimate"], new["spf"]["max_lookup_path_estimate"]
        if a != b:
            change(domain, "spf.max_lookup_path_estimate", a, b,
                   "medium" if b > 10 and b > a else "info", "Conservative SPF dependency lookup estimate changed")
        for k in ("mode", "valid"):
            a, b = old["mta_sts"].get(k), new["mta_sts"].get(k)
            if a != b:
                weakens = _STS.get(b, -1) < _STS.get(a, -1) if k == "mode" else a and not b
                change(domain, f"mta_sts.{k}", a, b, "high" if weakens else "info", "Captured MTA-STS posture changed")
        a, b = old["mta_sts"].get("mx"), new["mta_sts"].get("mx")
        if a is not None and b is not None and a != b:
            change(domain, "mta_sts.mx", a, b, "medium", "MTA-STS accepted MX patterns changed; confirm intended routing")
        a, b = old["mta_sts"].get("max_age"), new["mta_sts"].get("max_age")
        if a is not None and b is not None and a != b:
            change(domain, "mta_sts.max_age", a, b, "low" if b < a else "info", "MTA-STS cache lifetime changed")

    changes.sort(key=lambda x: (x["domain"], x["field"]))
    return {"tool": "mailauth-drift", "schema_version": 1, "changes": changes,
            "regressions": [c for c in changes if c["severity"] in {"low", "medium", "high", "critical"}],
            "candidate_findings": after["findings"]}
