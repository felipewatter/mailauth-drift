"""Deterministic, safe-to-render JSON, text and SARIF output."""

from __future__ import annotations

import json
from typing import Any

from .scanner import SEVERITIES


def threshold(findings: list[dict[str, Any]], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    return any(SEVERITIES.index(item["severity"]) >= SEVERITIES.index(fail_on) for item in findings)


def render_text(report: dict[str, Any]) -> str:
    if "findings" in report:
        lines = [f"MailAuth Drift | {len(report['domains'])} domains | {len(report['findings'])} findings"]
        for f in report["findings"]:
            lines.append(f"[{f['severity'].upper():8s}] {f['rule_id']} {f['domain']} | {f['message']} | {f['location']}")
        return "\n".join(lines) + "\n"
    lines = [f"MailAuth Drift | {len(report['changes'])} policy changes | {len(report['regressions'])} review-required changes"]
    for c in report["changes"]:
        lines.append(f"[{c['severity'].upper():8s}] {c['domain']}: {c['field']} | {c['before']} -> {c['after']}")
    return "\n".join(lines) + "\n"


def sarif(report: dict[str, Any]) -> dict[str, Any]:
    if "findings" not in report:
        raise ValueError("SARIF is only valid for scan reports")
    rules = sorted({f["rule_id"] for f in report["findings"]})
    results = []
    for finding in report["findings"]:
        severity = finding["severity"]
        results.append({"ruleId": finding["rule_id"], "level": "error" if severity in ("high", "critical") else "warning" if severity == "medium" else "note",
                        "message": {"text": finding["message"]},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "snapshot.json"}}}],
                        "properties": {"domain": finding["domain"], "dnsOwner": finding["location"],
                                       "severity": severity, "evidence": finding["evidence"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "MailAuth Drift", "version": "0.1.0",
                                         "informationUri": "https://github.com/felipewatter/mailauth-drift",
                                         "rules": [{"id": r, "shortDescription": {"text": r}} for r in rules]}},
                      "results": results}]}


def render(report: dict[str, Any], fmt: str) -> str:
    if fmt == "text":
        return render_text(report)
    if fmt == "json":
        return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if fmt == "sarif":
        return json.dumps(sarif(report), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    raise ValueError("unsupported output format")
