"""Command-line interface for solguard-cli (`solguard scan`, `solguard rules`, `solguard layout`)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from solguard import __version__
from solguard.engine import AnalyzerEngine
from solguard.models import Severity
from solguard.reporter import format_report, format_storage_layout_table
from solguard.rules import get_all_rules


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level `argparse.ArgumentParser` for `solguard`."""
    parser = argparse.ArgumentParser(
        prog="solguard",
        description="Defensive Solidity static analyzer and EVM storage-layout gas linter.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"solguard {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # `solguard scan <path>`
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a Solidity file or directory for security and gas findings.",
    )
    scan_parser.add_argument(
        "path",
        help="Path to a `.sol` file or directory containing Solidity contracts.",
    )
    scan_parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="Output report format (default: text).",
    )
    scan_parser.add_argument(
        "--severity",
        choices=("low", "medium", "high"),
        default="low",
        help="Minimum finding severity to report (default: low).",
    )
    scan_parser.add_argument(
        "--fail-on",
        dest="fail_on",
        choices=("low", "medium", "high", "none"),
        default="none",
        help="Return exit code 1 if any finding meets or exceeds this severity (default: none).",
    )
    scan_parser.add_argument(
        "--rule",
        dest="rules",
        action="append",
        default=None,
        help="Run only specific rule ID(s), e.g., `--rule SG001 --rule SG005`.",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Optional output file path to write the formatted report.",
    )

    # `solguard rules`
    rules_parser = subparsers.add_parser(
        "rules",
        help="List all built-in security and gas optimization rules.",
    )
    rules_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format for rule catalog (default: text).",
    )

    # `solguard layout <path>`
    layout_parser = subparsers.add_parser(
        "layout",
        help="Inspect 32-byte EVM storage slot layout and packing efficiency.",
    )
    layout_parser.add_argument(
        "path",
        help="Path to a `.sol` file or directory.",
    )
    layout_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format for storage layout (default: text).",
    )

    return parser


def _handle_scan(args: argparse.Namespace) -> int:
    min_severity = Severity.from_str(args.severity)
    fail_on: Severity | None = (
        None if args.fail_on == "none" else Severity.from_str(args.fail_on)
    )
    enabled_ids = set(args.rules) if args.rules else None

    engine = AnalyzerEngine(
        min_severity=min_severity,
        enabled_rule_ids=enabled_ids,
    )

    try:
        report = engine.scan_path(args.path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    rendered = format_report(report, args.format)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if report.should_fail(fail_on):
        return 1
    return 0


def _handle_rules(args: argparse.Namespace) -> int:
    catalog = get_all_rules()
    if args.format == "json":
        payload = [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "severity": r.severity.value,
                "category": r.category.value,
                "description": r.description,
                "remediation": r.remediation,
            }
            for r in catalog
        ]
        print(json.dumps(payload, indent=2))
        return 0

    print(f"{'ID':<7} {'SEVERITY':<9} {'CATEGORY':<14} {'TITLE'}")
    print("-" * 72)
    for rule in catalog:
        print(
            f"{rule.rule_id:<7} {rule.severity.value.upper():<9} "
            f"{rule.category.value:<14} {rule.title}"
        )
    return 0


def _handle_layout(args: argparse.Namespace) -> int:
    engine = AnalyzerEngine()
    try:
        report = engine.scan_path(args.path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        payload = [layout.to_dict() for layout in report.storage_layouts]
        print(json.dumps(payload, indent=2))
    else:
        print(format_storage_layout_table(report.storage_layouts))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the `solguard` CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _handle_scan(args)
    if args.command == "rules":
        return _handle_rules(args)
    if args.command == "layout":
        return _handle_layout(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
