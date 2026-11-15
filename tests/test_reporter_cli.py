"""Integration tests for text, JSON, SARIF v2.1.0 reporters and CLI exit behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from solguard.cli import main
from solguard.engine import AnalyzerEngine
from solguard.reporter import (
    SARIF_SCHEMA_URL,
    SARIF_VERSION,
    format_json_report,
    format_sarif_report,
    format_text_report,
)


def test_format_text_report_contains_summary_and_rule_ids(
    vulnerable_vault_path: Path,
) -> None:
    report = AnalyzerEngine().scan_path(vulnerable_vault_path)
    text_out = format_text_report(report)
    assert "SolGuard Static Analysis Report" in text_out
    assert "SG001" in text_out
    assert "SG002" in text_out
    assert "SG003" in text_out
    assert "Summary:" in text_out


def test_format_json_report_structure(gas_inefficient_path: Path) -> None:
    report = AnalyzerEngine().scan_path(gas_inefficient_path)
    payload = json.loads(format_json_report(report))
    assert payload["tool"] == "solguard-cli"
    assert payload["summary"]["files_scanned"] == 1
    assert payload["summary"]["contracts_scanned"] == 1
    assert payload["summary"]["total_findings"] >= 3
    assert isinstance(payload["findings"], list)
    assert isinstance(payload["storage_layouts"], list)


def test_format_sarif_v2_1_0_schema_compliance(vulnerable_vault_path: Path) -> None:
    report = AnalyzerEngine().scan_path(vulnerable_vault_path)
    sarif = json.loads(format_sarif_report(report))
    assert sarif["$schema"] == SARIF_SCHEMA_URL
    assert sarif["version"] == SARIF_VERSION
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "solguard-cli"
    rule_ids = {r["id"] for r in driver["rules"]}
    assert rule_ids == {"SG001", "SG002", "SG003", "SG004", "SG005"}

    results = run["results"]
    assert len(results) >= 4
    first = results[0]
    assert "ruleId" in first
    assert first["level"] in {"error", "warning", "note"}
    loc = first["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"].endswith("vulnerable_vault.sol")
    assert loc["region"]["startLine"] >= 1


def test_cli_scan_exit_code_with_fail_on_high(
    vulnerable_vault_path: Path,
    clean_vault_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Vulnerable vault has HIGH findings -> exit code 1 when `--fail-on high`
    rc_fail = main(
        ["scan", str(vulnerable_vault_path), "--format", "json", "--fail-on", "high"]
    )
    captured = capsys.readouterr()
    assert rc_fail == 1
    parsed = json.loads(captured.out)
    assert parsed["summary"]["by_severity"]["high"] > 0

    # Clean vault has 0 findings -> exit code 0 when `--fail-on high`
    rc_ok = main(
        ["scan", str(clean_vault_path), "--format", "text", "--fail-on", "high"]
    )
    _ = capsys.readouterr()
    assert rc_ok == 0


def test_cli_severity_filter_and_output_file(
    fixtures_dir: Path,
    tmp_path: Path,
) -> None:
    sarif_file = tmp_path / "report.sarif"
    rc = main(
        [
            "scan",
            str(fixtures_dir),
            "--format",
            "sarif",
            "--severity",
            "high",
            "--output",
            str(sarif_file),
        ]
    )
    assert rc == 0
    assert sarif_file.exists()
    doc = json.loads(sarif_file.read_text(encoding="utf-8"))
    levels = {r["level"] for r in doc["runs"][0]["results"]}
    assert levels == {"error"}


def test_cli_rules_and_layout_subcommands(
    gas_inefficient_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc_rules = main(["rules", "--format", "json"])
    rules_out = json.loads(capsys.readouterr().out)
    assert rc_rules == 0
    assert len(rules_out) == 5

    rc_layout = main(["layout", str(gas_inefficient_path), "--format", "text"])
    layout_out = capsys.readouterr().out
    assert rc_layout == 0
    assert "GasInefficientRegistry" in layout_out
    assert "OrderRecord" in layout_out


def test_cli_missing_target_returns_exit_code_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = main(["scan", "nonexistent_contract.sol"])
    _ = capsys.readouterr()
    assert rc == 2
