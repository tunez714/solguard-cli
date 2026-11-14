"""Terminal table, JSON, and OASIS SARIF v2.1.0 report exporters."""

from __future__ import annotations

import json
from typing import Any

from solguard import __version__
from solguard.models import ScanReport, StorageLayout
from solguard.rules import BaseRule, get_all_rules

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def format_text_report(report: ScanReport) -> str:
    """Format a human-readable terminal table and summary for `report`."""
    lines: list[str] = []
    lines.append(f"SolGuard Static Analysis Report (v{__version__})")
    lines.append("=" * 88)
    lines.append(
        f"Target: {report.target_path} | Files: {report.files_scanned} | Contracts: {report.contracts_scanned}"
    )
    lines.append("-" * 88)

    if not report.findings:
        lines.append("No security or gas findings detected.")
    else:
        header = f"{'RULE':<7} {'SEVERITY':<9} {'CONTRACT':<20} {'LOCATION':<26} {'MESSAGE'}"
        lines.append(header)
        lines.append("-" * 88)
        for finding in report.findings:
            loc_str = f"{finding.location.file_path}:{finding.location.line}"
            if len(loc_str) > 25:
                loc_str = "..." + loc_str[-22:]
            sev_label = finding.severity.value.upper()
            contract_label = finding.contract_name[:19]
            lines.append(
                f"{finding.rule_id:<7} {sev_label:<9} {contract_label:<20} {loc_str:<26} {finding.message}"
            )
            if finding.location.snippet:
                lines.append(f"        snippet: {finding.location.snippet}")
            lines.append(f"        fix:     {finding.remediation}")
            lines.append("")

    counts = report.count_by_severity()
    lines.append("-" * 88)
    lines.append(
        f"Summary: {len(report.findings)} finding(s) "
        f"[HIGH: {counts['high']}, MEDIUM: {counts['medium']}, LOW: {counts['low']}]"
    )
    return "\n".join(lines)


def format_json_report(report: ScanReport) -> str:
    """Serialize `report` into a deterministic JSON string."""
    payload: dict[str, Any] = {
        "tool": "solguard-cli",
        "version": __version__,
        "target_path": report.target_path,
        "summary": {
            "files_scanned": report.files_scanned,
            "contracts_scanned": report.contracts_scanned,
            "total_findings": len(report.findings),
            "by_severity": report.count_by_severity(),
        },
        "findings": [finding.to_dict() for finding in report.findings],
        "storage_layouts": [layout.to_dict() for layout in report.storage_layouts],
    }
    return json.dumps(payload, indent=2)


def format_sarif_report(
    report: ScanReport,
    rules: list[BaseRule] | None = None,
) -> str:
    """Serialize `report` as an OASIS SARIF v2.1.0 JSON document for CI pipelines."""
    catalog = rules if rules is not None else get_all_rules()

    sarif_rules: list[dict[str, Any]] = []
    for rule in catalog:
        sarif_rules.append(
            {
                "id": rule.rule_id,
                "name": rule.title.replace(" ", ""),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.remediation},
                "defaultConfiguration": {"level": rule.severity.sarif_level},
                "properties": {
                    "category": rule.category.value,
                    "severity": rule.severity.value,
                    "tags": ["solidity", "evm", rule.category.value],
                },
            }
        )

    sarif_results: list[dict[str, Any]] = []
    for finding in report.findings:
        sarif_results.append(
            {
                "ruleId": finding.rule_id,
                "level": finding.severity.sarif_level,
                "message": {"text": f"{finding.message} Remediation: {finding.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.location.file_path,
                            },
                            "region": {
                                "startLine": finding.location.line,
                                "startColumn": finding.location.column,
                                "endLine": finding.location.end_line or finding.location.line,
                                "endColumn": finding.location.end_column or finding.location.column,
                                "snippet": {"text": finding.location.snippet},
                            },
                        }
                    }
                ],
                "properties": {
                    "contract": finding.contract_name,
                    "function": finding.function_name,
                    "severity": finding.severity.value,
                    "category": finding.category.value,
                    **finding.metadata,
                },
            }
        )

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "solguard-cli",
                        "version": __version__,
                        "informationUri": "https://github.com/tunez714/solguard-cli",
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def format_storage_layout_table(layouts: list[StorageLayout]) -> str:
    """Format EVM 32-byte storage slot allocations into a readable terminal table."""
    if not layouts:
        return "No stateful contracts or structs found."

    lines: list[str] = []
    for layout in layouts:
        lines.append(
            f"{layout.kind.upper()} `{layout.target_name}` (line {layout.line}) — "
            f"Current Slots: {layout.total_slots} | Optimal Slots: {layout.optimal_slots} | "
            f"Potential Savings: {layout.slots_saved} slot(s) (~{layout.estimated_gas_saved:,} gas)"
        )
        lines.append("-" * 78)
        lines.append(f"{'SLOT':<6} {'USED (B)':<10} {'FREE (B)':<10} {'PACKED VARIABLES (OFFSET: TYPE NAME [BYTES])'}")
        for slot in layout.slots:
            items_desc = ", ".join(
                f"+{item.byte_offset}B: {item.type_name} {item.name} [{item.byte_size}B]"
                for item in slot.items
            )
            lines.append(
                f"{slot.slot_index:<6} {slot.used_bytes:<10} {slot.free_bytes:<10} {items_desc}"
            )
        lines.append("")
    return "\n".join(lines).rstrip()


def format_report(report: ScanReport, output_format: str) -> str:
    """Dispatch report formatting based on `output_format` (`text`, `json`, `sarif`)."""
    fmt = output_format.strip().lower()
    if fmt == "text":
        return format_text_report(report)
    if fmt == "json":
        return format_json_report(report)
    if fmt == "sarif":
        return format_sarif_report(report)
    raise ValueError(f"Unsupported output format '{output_format}'. Expected text, json, or sarif.")
