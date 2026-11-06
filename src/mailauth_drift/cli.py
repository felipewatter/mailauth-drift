"""Command line interface with non-ambiguous security-gate exit codes."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .diff import compare
from .reports import render, threshold
from .scanner import SEVERITIES, scan
from .snapshot import SnapshotError, load_snapshot, name


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mailauth-drift", description="Offline email authentication policy regression engine")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("scan", help="Inspect an offline snapshot")
    a.add_argument("--snapshot", required=True)
    a.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    a.add_argument("--fail-on", choices=("none",) + SEVERITIES, default="high")
    a.add_argument("--output", help="Write report into a local file")
    b = sub.add_parser("diff", help="Flag regressions between two captured policy snapshots")
    b.add_argument("--baseline", required=True)
    b.add_argument("--candidate", required=True)
    b.add_argument("--format", choices=("text", "json"), default="text")
    b.add_argument("--fail-on-regression", action="store_true")
    b.add_argument("--output", help="Write comparison into a local file")
    c = sub.add_parser("trace", help="Explain SPF dependency references from snapshot")
    c.add_argument("--snapshot", required=True)
    c.add_argument("--domain", required=True)
    c.add_argument("--format", choices=("text", "json"), default="text")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            report = scan(load_snapshot(args.snapshot))
            result = render(report, args.format)
            should_fail = threshold(report["findings"], args.fail_on)
        elif args.command == "diff":
            report = compare(load_snapshot(args.baseline), load_snapshot(args.candidate))
            result = render(report, args.format)
            should_fail = bool(args.fail_on_regression and report["regressions"])
        else:
            report = scan(load_snapshot(args.snapshot))
            domain = name(args.domain)
            if domain not in report["domains"]:
                raise SnapshotError(f"domain {domain!r} is not in snapshot")
            graph = report["domains"][domain]["spf"]
            result = (json.dumps(graph, indent=2, sort_keys=True) + "\n") if args.format == "json" else (
                f"{domain} | SPF terminal={graph['terminal']} | estimated lookups={graph['max_lookup_path_estimate']}\n"
                + "".join(f"  {e['from']} --{e['mechanism']}--> {e['to']}\n" for e in graph["edges"]))
            should_fail = False
        if getattr(args, "output", None):
            dest = Path(args.output)
            if dest.is_symlink():
                raise SnapshotError("refusing to write report into a symlink")
            dest.write_text(result, encoding="utf-8")
        else:
            sys.stdout.write(result)
        return 1 if should_fail else 0
    except (SnapshotError, OSError, ValueError) as exc:
        print(f"mailauth-drift: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
