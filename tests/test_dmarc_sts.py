from __future__ import annotations

import copy

import pytest

from mailauth_drift.scanner import scan
from mailauth_drift.snapshot import parse_snapshot


def mutate(baseline, dmarc=None, sts_txt=None, sts_policy="unchanged"):
    x = copy.deepcopy(baseline)
    cfg = x["domains"]["example.com"]
    if dmarc is not None:
        cfg["txt"]["_dmarc.example.com"] = dmarc
    if sts_txt is not None:
        cfg["txt"]["_mta-sts.example.com"] = sts_txt
    if sts_policy != "unchanged":
        cfg["mta_sts_policy"] = sts_policy
    return scan(parse_snapshot(x))


def rules(r):
    return [f["rule_id"] for f in r["findings"]]


def test_baseline_valid(baseline):
    r = mutate(baseline)
    assert r["domains"]["example.com"]["dmarc"]["valid"]
    assert r["domains"]["example.com"]["mta_sts"]["valid"]


@pytest.mark.parametrize("policy", ["none", "quarantine", "reject"])
def test_dmarc_policies(baseline, policy):
    d = mutate(baseline, [f"v=DMARC1; p={policy}; rua=mailto:x@example.com"])["domains"]["example.com"]["dmarc"]
    assert d["p"] == policy
    assert d["sp"] == policy
    assert d["np"] == policy


@pytest.mark.parametrize("value", [
    ["v=DMARC1; p=garbage"], ["v=DMARC1; p=reject; adkim=x"],
    ["v=DMARC1; p=reject; aspf=x"], ["v=DMARC1; p=reject; t=x"],
    ["v=DMARC1; p=reject; p=none"], ["v=DMARC1; rua=mailto:a@b"],
    ["v=DMARC1; p=reject; noequals"], ["v=DMARC1; p=reject; np=bad"],
])
def test_dmarc_invalid(baseline, value):
    assert "MAD-DMARC-SYNTAX" in rules(mutate(baseline, value))


def test_dmarc_missing(baseline):
    assert "MAD-DMARC-MISSING" in rules(mutate(baseline, []))


def test_dmarc_multiple(baseline):
    assert "MAD-DMARC-MULTIPLE" in rules(mutate(baseline, ["v=DMARC1; p=none", "v=DMARC1; p=reject"]))


def test_dmarc_monitor(baseline):
    assert "MAD-DMARC-MONITOR" in rules(mutate(baseline, ["v=DMARC1; p=none"]))


def test_dmarc_t_tag(baseline):
    assert "MAD-DMARC-TEST" in rules(mutate(baseline, ["v=DMARC1; p=reject; t=y"]))


@pytest.mark.parametrize("tag", ["pct=50", "rf=afrf", "ri=3600"])
def test_historic_dmarc_tags(baseline, tag):
    assert "MAD-DMARC-HISTORIC" in rules(mutate(baseline, [f"v=DMARC1; p=reject; {tag}"]))


def test_dmarc_missing_rua(baseline):
    assert "MAD-DMARC-REPORT" in rules(mutate(baseline, ["v=DMARC1; p=reject"]))


def test_sts_missing(baseline):
    assert "MAD-STS-MISSING" in rules(mutate(baseline, sts_txt=[], sts_policy=None))


def test_sts_dns_missing(baseline):
    assert "MAD-STS-DNS" in rules(mutate(baseline, sts_txt=[]))


def test_sts_policy_missing(baseline):
    assert "MAD-STS-POLICY" in rules(mutate(baseline, sts_policy=None))


@pytest.mark.parametrize("mode,rule", [("testing", "MAD-STS-TEST"), ("none", "MAD-STS-OFF")])
def test_sts_modes(baseline, mode, rule):
    policy = copy.deepcopy(baseline["domains"]["example.com"]["mta_sts_policy"])
    policy["mode"] = mode
    assert rule in rules(mutate(baseline, sts_policy=policy))


def test_sts_invalid_mode(baseline):
    policy = copy.deepcopy(baseline["domains"]["example.com"]["mta_sts_policy"])
    policy["mode"] = "super-enforce"
    assert "MAD-STS-POLICY" in rules(mutate(baseline, sts_policy=policy))


def test_sts_no_mx(baseline):
    policy = copy.deepcopy(baseline["domains"]["example.com"]["mta_sts_policy"])
    policy["mx"] = []
    assert "MAD-STS-POLICY" in rules(mutate(baseline, sts_policy=policy))


def test_sts_dns_absence_prevents_valid_state(baseline):
    d = mutate(baseline, sts_txt=[])["domains"]["example.com"]["mta_sts"]
    assert d["valid"] is False


def test_sts_duplicate_record_prevents_valid_state(baseline):
    d = mutate(baseline, sts_txt=["v=STSv1; id=a", "v=STSv1; id=b"])["domains"]["example.com"]["mta_sts"]
    assert d["valid"] is False
