"""Strict, bounded, offline DNS/SMTP policy snapshots.

Never perform DNS queries or fetch MTA-STS policies. Only the supplied JSON is consulted.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_BYTES = 2 * 1024 * 1024
MAX_DOMAINS = 128
MAX_TXT_NAMES = 2048
MAX_TXT_RECORDS = 4096
MAX_TXT_LENGTH = 4096
_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


class SnapshotError(ValueError):
    """Invalid or unsupported snapshot; avoid returning a partial assessment."""


def name(value: str) -> str:
    if not isinstance(value, str) or len(value) > 255 or not value.strip():
        raise SnapshotError("invalid domain name")
    v = value.rstrip(".").lower()
    try:
        labels = v.split(".")
        labels = [label.encode("idna").decode("ascii") for label in labels]
    except UnicodeError as exc:
        raise SnapshotError("invalid internationalized DNS name") from exc
    if not all(0 < len(label) <= 63 and _LABEL.fullmatch(label) for label in labels):
        raise SnapshotError(f"invalid DNS label in {value!r}")
    if len(".".join(labels)) > 253:
        raise SnapshotError("DNS name exceeds limit")
    return ".".join(labels)


@dataclass(frozen=True)
class DomainSnapshot:
    domain: str
    txt: dict[str, tuple[str, ...]]
    mta_sts_policy: dict[str, Any] | None


@dataclass(frozen=True)
class Snapshot:
    domains: dict[str, DomainSnapshot]


def parse_snapshot(document: Any) -> Snapshot:
    if not isinstance(document, dict) or set(document) != {"schema_version", "domains"}:
        raise SnapshotError("snapshot requires exactly schema_version and domains")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise SnapshotError("unsupported schema version (expected 1)")
    domains = document["domains"]
    if not isinstance(domains, dict) or not 1 <= len(domains) <= MAX_DOMAINS:
        raise SnapshotError("domains must be a nonempty object with at most 128 entries")
    result: dict[str, DomainSnapshot] = {}
    names_count, records_count = 0, 0
    for raw_domain, config in domains.items():
        domain = name(raw_domain)
        if domain in result or not isinstance(config, dict):
            raise SnapshotError("duplicate normalized domain or invalid domain object")
        if not set(config).issubset({"txt", "mta_sts_policy"}):
            raise SnapshotError(f"unexpected fields for {domain}")
        raw_txt = config.get("txt", {})
        if not isinstance(raw_txt, dict):
            raise SnapshotError("txt must be an object mapping FQDNs to TXT record arrays")
        txt: dict[str, tuple[str, ...]] = {}
        for raw_name, values in raw_txt.items():
            n = name(raw_name)
            names_count += 1
            if n in txt or not isinstance(values, list):
                raise SnapshotError("duplicate normalized TXT name or invalid TXT array")
            records_count += len(values)
            if not all(isinstance(v, str) and 0 < len(v) <= MAX_TXT_LENGTH for v in values):
                raise SnapshotError("TXT values must be nonempty strings <=4096 bytes")
            txt[n] = tuple(values)
        policy = config.get("mta_sts_policy")
        if policy is not None:
            if not isinstance(policy, dict) or not set(policy).issubset({"version", "mode", "max_age", "mx"}):
                raise SnapshotError("mta_sts_policy must be object with approved fields")
            if not isinstance(policy.get("version"), str) or not isinstance(policy.get("mode"), str):
                raise SnapshotError("mta_sts_policy version and mode must be strings")
            if type(policy.get("max_age")) is not int or not 0 <= policy["max_age"] <= 31557600:
                raise SnapshotError("mta_sts_policy max_age must be integer in [0,31557600]")
            mx = policy.get("mx")
            if not isinstance(mx, list) or len(mx) > 100 or not all(isinstance(v, str) for v in mx):
                raise SnapshotError("mta_sts_policy mx must be an array of strings")
            for host in mx:
                name(host.removeprefix("*."))
        result[domain] = DomainSnapshot(domain, txt, policy)
    if names_count > MAX_TXT_NAMES or records_count > MAX_TXT_RECORDS:
        raise SnapshotError("TXT snapshot exceeds safe limits")
    return Snapshot(result)


def load_snapshot(path: str | Path) -> Snapshot:
    p = Path(path)
    try:
        if not p.is_file():
            raise SnapshotError("snapshot path is not a regular file")
        with p.open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise SnapshotError("snapshot exceeds 2 MiB limit")
        document = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"could not read snapshot: {exc}") from exc
    return parse_snapshot(document)
