from __future__ import annotations

import json

import pytest

from mailauth_drift.snapshot import SnapshotError, load_snapshot, name, parse_snapshot


@pytest.mark.parametrize("value,expected", [
    ("Example.COM.", "example.com"), ("bücher.example", "xn--bcher-kva.example"),
    ("_dmarc.Example.com", "_dmarc.example.com"), ("_spf.example.com", "_spf.example.com"),
])
def test_normalize(value, expected):
    assert name(value) == expected


@pytest.mark.parametrize("value", ["", ".", "..", "a..b", "x" * 64 + ".example", "bad name.org", 
                                     "example.com/secret", "bad@example.org", 42])
def test_reject_bad_names(value):
    with pytest.raises(SnapshotError):
        name(value)


def test_load_baseline(baseline):
    parsed = parse_snapshot(baseline)
    assert "example.com" in parsed.domains
    assert parsed.domains["example.com"].mta_sts_policy["mode"] == "enforce"


@pytest.mark.parametrize("patch", [
    {}, {"schema_version": 2, "domains": {"example.com": {}}},
    {"schema_version": True, "domains": {"example.com": {}}},
    {"schema_version": 1, "domains": []},
    {"schema_version": 1, "domains": {}},
    {"schema_version": 1, "domains": {"example.com": {"bad": 1}}},
    {"schema_version": 1, "domains": {"example.com": {"txt": []}}},
    {"schema_version": 1, "domains": {"example.com": {"txt": {"a": [None]}}}},
    {"schema_version": 1, "domains": {"example.com": {"txt": {"a": ["x" * 4097]}}}},
    {"schema_version": 1, "domains": {"example.com": {"mta_sts_policy": {"version": "STSv1", "mode": "enforce", "max_age": "1", "mx": []}}}},
    {"schema_version": 1, "domains": {"example.com": {"mta_sts_policy": {"version": "STSv1", "mode": "enforce", "max_age": True, "mx": []}}}},
])
def test_reject_invalid_schema(patch):
    with pytest.raises(SnapshotError):
        parse_snapshot(patch)


def test_normalized_duplicate_domain():
    with pytest.raises(SnapshotError):
        parse_snapshot({"schema_version": 1, "domains": {"A.org": {}, "a.ORG.": {}}})


def test_normalized_duplicate_txt():
    with pytest.raises(SnapshotError):
        parse_snapshot({"schema_version": 1, "domains": {"a.org": {"txt": {"a.org": [], "A.org.": []}}}})


def test_too_many_domains():
    with pytest.raises(SnapshotError):
        parse_snapshot({"schema_version": 1, "domains": {f"a{i}.test": {} for i in range(129)}})


def test_file_size(tmp_path):
    p = tmp_path / "huge.json"
    p.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    with pytest.raises(SnapshotError, match="2 MiB"):
        load_snapshot(p)


def test_bad_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{broken")
    with pytest.raises(SnapshotError):
        load_snapshot(p)


def test_read_json(tmp_path, baseline):
    p = tmp_path / "snapshot.json"
    p.write_text(json.dumps(baseline))
    assert load_snapshot(p).domains
