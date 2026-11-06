from __future__ import annotations

import copy

import pytest

from mailauth_drift.scanner import scan
from mailauth_drift.snapshot import parse_snapshot


def run(baseline, root=None, others=None):
    x = copy.deepcopy(baseline)
    records = x["domains"]["example.com"]["txt"]
    if root is not None:
        records["example.com"] = root
    if others:
        records.update(others)
    return scan(parse_snapshot(x))


def ids(report):
    return [f["rule_id"] for f in report["findings"]]


def test_baseline_clean(baseline):
    r = run(baseline)
    assert r["findings"] == []
    assert r["domains"]["example.com"]["spf"]["max_lookup_path_estimate"] == 1


@pytest.mark.parametrize("term,rule,severity", [
    ("+all", "MAD-SPF-ALLOWALL", "critical"),
    ("~all", "MAD-SPF-WEAK", "low"),
    ("?all", "MAD-SPF-WEAK", "medium"),
    ("all", "MAD-SPF-ALLOWALL", "critical"),
])
def test_terminal_weakness(baseline, term, rule, severity):
    r = run(baseline, [f"v=spf1 {term}"])
    assert any(f["rule_id"] == rule and f["severity"] == severity for f in r["findings"])


def test_missing(baseline):
    assert "MAD-SPF-MISSING" in ids(run(baseline, []))


def test_multiple(baseline):
    assert "MAD-SPF-MULTIPLE" in ids(run(baseline, ["v=spf1 -all", "v=spf1 +all"]))


def test_cycle(baseline):
    r = run(baseline, ["v=spf1 include:a.example.com -all"], {"a.example.com": ["v=spf1 include:example.com -all"]})
    assert "MAD-SPF-CYCLE" in ids(r)
    assert r["domains"]["example.com"]["spf"]["incomplete"] is True


def test_missing_ref(baseline):
    assert "MAD-SPF-REF" in ids(run(baseline, ["v=spf1 include:outside.test -all"]))


def test_ptr(baseline):
    assert "MAD-SPF-PTR" in ids(run(baseline, ["v=spf1 ptr -all"]))


def test_invalid_ip(baseline):
    assert "MAD-SPF-SYNTAX" in ids(run(baseline, ["v=spf1 ip4:127.0.0.500 -all"]))


def test_ip_mismatch(baseline):
    assert "MAD-SPF-SYNTAX" in ids(run(baseline, ["v=spf1 ip6:127.0.0.1 -all"]))


def test_ipv6_good(baseline):
    assert not ids(run(baseline, ["v=spf1 ip6:2001:db8::/48 -all"]))


def test_missing_terminator(baseline):
    assert "MAD-SPF-NEUTRAL" in ids(run(baseline, ["v=spf1 mx"]))


def test_unknown_term(baseline):
    assert "MAD-SPF-SYNTAX" in ids(run(baseline, ["v=spf1 foo:abc -all"]))


def test_all_not_end(baseline):
    assert "MAD-SPF-TERMINATOR" in ids(run(baseline, ["v=spf1 -all ip4:127.0.0.1"]))


def test_redirect_and_all(baseline):
    assert "MAD-SPF-REDIRECT" in ids(run(baseline, ["v=spf1 -all redirect=_spf.example.com"]))


def test_missing_redirect(baseline):
    assert "MAD-SPF-REF" in ids(run(baseline, ["v=spf1 redirect=missing.example.com"]))


def test_dynamic_macro(baseline):
    assert "MAD-SPF-DYNAMIC" in ids(run(baseline, ["v=spf1 include:%{d}.example.com -all"]))


def test_lookup_estimate(baseline):
    r = run(baseline, ["v=spf1 " + ("mx " * 11) + "-all"])
    assert "MAD-SPF-LOOKUPS" in ids(r)
    assert r["domains"]["example.com"]["spf"]["max_lookup_path_estimate"] == 11


def test_trace_edges(baseline):
    edges = run(baseline)["domains"]["example.com"]["spf"]["edges"]
    assert edges == [{"from": "example.com", "to": "_spf.example.com", "mechanism": "include"}]


def test_nested_ref_depth(baseline):
    others = {f"n{i}.example.com": [f"v=spf1 include:n{i+1}.example.com -all"] for i in range(25)}
    r = run(baseline, ["v=spf1 include:n0.example.com -all"], others)
    assert "MAD-SPF-DEPTH" in ids(r)
