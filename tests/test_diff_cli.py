from __future__ import annotations

import copy
import json
import subprocess
import sys

from mailauth_drift.cli import main
from mailauth_drift.diff import compare
from mailauth_drift.reports import render, sarif, threshold
from mailauth_drift.scanner import scan
from mailauth_drift.snapshot import parse_snapshot


def test_diff_regressions(baseline, candidate):
    report = compare(parse_snapshot(baseline), parse_snapshot(candidate))
    assert len(report["regressions"]) >= 8
    assert {r["field"] for r in report["regressions"]} >= {"dmarc.p", "spf.terminal", "mta_sts.mode"}


def test_diff_no_changes(baseline):
    report = compare(parse_snapshot(baseline), parse_snapshot(baseline))
    assert not report["changes"]


def test_diff_removed_domain(baseline):
    c = copy.deepcopy(baseline)
    c["domains"] = {"other.test": {}}
    report = compare(parse_snapshot(baseline), parse_snapshot(c))
    assert any(e["after"] == "removed" for e in report["changes"])
    assert any(e["after"] == "present" for e in report["changes"])


def test_diff_strict_to_relaxed(baseline):
    c = copy.deepcopy(baseline)
    c["domains"]["example.com"]["txt"]["_dmarc.example.com"] = ["v=DMARC1; p=none"]
    assert "high" in [x["severity"] for x in compare(parse_snapshot(baseline), parse_snapshot(c))["changes"]]


def test_diff_spf_lookup_increase(baseline):
    c = copy.deepcopy(baseline)
    c["domains"]["example.com"]["txt"]["example.com"] = ["v=spf1 " + ("a " * 11) + "-all"]
    assert any(x["field"] == "spf.max_lookup_path_estimate" and x["severity"] == "medium"
               for x in compare(parse_snapshot(baseline), parse_snapshot(c))["changes"])


def test_deterministic_output(baseline):
    a = render(scan(parse_snapshot(baseline)), "json")
    assert a == render(scan(parse_snapshot(baseline)), "json")


def test_sarif_valid(baseline, candidate):
    report = scan(parse_snapshot(candidate))
    s = sarif(report)
    assert s["version"] == "2.1.0"
    assert len(s["runs"][0]["results"]) == len(report["findings"])
    assert json.loads(render(report, "sarif"))["runs"]


def test_threshold(baseline, candidate):
    clean = scan(parse_snapshot(baseline))["findings"]
    bad = scan(parse_snapshot(candidate))["findings"]
    assert not threshold(clean, "high")
    assert not threshold(bad, "none")
    assert threshold(bad, "high")


def test_cli_scan_clean(tmp_path, baseline):
    p = tmp_path / "snap.json"
    p.write_text(json.dumps(baseline))
    assert main(["scan", "--snapshot", str(p)]) == 0


def test_cli_diff_gate(tmp_path, baseline, candidate):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(baseline))
    b.write_text(json.dumps(candidate))
    assert main(["diff", "--baseline", str(a), "--candidate", str(b), "--fail-on-regression"]) == 1
    assert main(["diff", "--baseline", str(a), "--candidate", str(b)]) == 0


def test_cli_invalid_input(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("invalid")
    assert main(["scan", "--snapshot", str(p)]) == 2


def test_cli_missing_domain(tmp_path, baseline):
    p = tmp_path / "a.json"
    p.write_text(json.dumps(baseline))
    assert main(["trace", "--snapshot", str(p), "--domain", "absent.test"]) == 2


def test_cli_trace(tmp_path, baseline, capsys):
    p = tmp_path / "a.json"
    p.write_text(json.dumps(baseline))
    assert main(["trace", "--snapshot", str(p), "--domain", "example.com", "--format", "json"]) == 0
    assert "_spf.example.com" in capsys.readouterr().out


def test_cli_output_file(tmp_path, baseline):
    p, out = tmp_path / "a.json", tmp_path / "report.sarif"
    p.write_text(json.dumps(baseline))
    assert main(["scan", "--snapshot", str(p), "--format", "sarif", "--output", str(out)]) == 0
    assert json.loads(out.read_text())["version"] == "2.1.0"


def test_cli_symlink_output(tmp_path, baseline):
    p, target, out = tmp_path / "a.json", tmp_path / "target", tmp_path / "report.txt"
    p.write_text(json.dumps(baseline))
    target.write_text("preserve")
    out.symlink_to(target)
    assert main(["scan", "--snapshot", str(p), "--output", str(out)]) == 2
    assert target.read_text() == "preserve"


def test_python_module(tmp_path, baseline):
    p = tmp_path / "snap.json"
    p.write_text(json.dumps(baseline))
    result = subprocess.run([sys.executable, "-m", "mailauth_drift", "scan", "--snapshot", str(p)],
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
