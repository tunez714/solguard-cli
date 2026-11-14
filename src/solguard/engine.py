"""Static analysis orchestration engine for Solidity files and workspaces."""

from __future__ import annotations

from pathlib import Path

from solguard.models import Finding, ParsedContract, ScanReport, Severity, StorageLayout
from solguard.parser import SolidityParser
from solguard.rules import BaseRule, get_all_rules

_IGNORED_DIRS = {".git", "node_modules", "out", "cache", "artifacts", ".venv", "venv"}


def discover_solidity_files(target: str | Path) -> list[Path]:
    """Resolve `target` into a sorted list of `.sol` file paths."""
    path = Path(target)
    if not path.exists():
        raise FileNotFoundError(f"Scan target does not exist: {target}")

    if path.is_file():
        if path.suffix.lower() != ".sol":
            raise ValueError(f"Expected a `.sol` file, got: {target}")
        return [path]

    sol_files: list[Path] = []
    for candidate in sorted(path.rglob("*.sol")):
        if any(part in _IGNORED_DIRS for part in candidate.parts):
            continue
        if candidate.is_file():
            sol_files.append(candidate)
    return sol_files


def _is_suppressed(finding: Finding, contract: ParsedContract) -> bool:
    """Return True if the finding's line has a matching `solguard-disable` directive."""
    suppressed_rules = contract.suppressed_lines.get(finding.location.line)
    if not suppressed_rules:
        return False
    return "ALL" in suppressed_rules or finding.rule_id.upper() in suppressed_rules


class AnalyzerEngine:
    """Executes configured lint rules against parsed Solidity contracts."""

    def __init__(
        self,
        rules: list[BaseRule] | None = None,
        min_severity: Severity = Severity.LOW,
        enabled_rule_ids: set[str] | None = None,
    ) -> None:
        all_rules = rules if rules is not None else get_all_rules()
        normalized_ids = (
            {rid.strip().upper() for rid in enabled_rule_ids if rid.strip()}
            if enabled_rule_ids
            else None
        )
        self.min_severity = min_severity
        self.rules = [
            rule
            for rule in all_rules
            if rule.severity.meets_threshold(min_severity)
            and (normalized_ids is None or rule.rule_id.upper() in normalized_ids)
        ]
        self.parser = SolidityParser()

    def analyze_contract(self, contract: ParsedContract) -> list[Finding]:
        """Run all active rules against a single `ParsedContract`."""
        findings: list[Finding] = []
        for rule in self.rules:
            for finding in rule.analyze(contract):
                if not _is_suppressed(finding, contract):
                    findings.append(finding)

        findings.sort(
            key=lambda f: (
                f.location.file_path,
                f.location.line,
                -f.severity.rank,
                f.rule_id,
            )
        )
        return findings

    def scan_source(
        self,
        source: str,
        file_path: str = "<memory>",
    ) -> ScanReport:
        """Parse and analyze an in-memory Solidity source string."""
        contracts = self.parser.parse_source(source, file_path=file_path)
        findings: list[Finding] = []
        layouts: list[StorageLayout] = []

        for contract in contracts:
            findings.extend(self.analyze_contract(contract))
            if contract.storage_layout.total_slots > 0:
                layouts.append(contract.storage_layout)
            for struct in contract.structs:
                if struct.storage_layout.total_slots > 0:
                    layouts.append(struct.storage_layout)

        return ScanReport(
            target_path=file_path,
            files_scanned=1,
            contracts_scanned=len(contracts),
            findings=findings,
            storage_layouts=layouts,
        )

    def scan_path(self, target: str | Path) -> ScanReport:
        """Discover `.sol` files under `target` and run all active rules."""
        sol_files = discover_solidity_files(target)
        all_findings: list[Finding] = []
        all_layouts: list[StorageLayout] = []
        contracts_count = 0

        for sol_file in sol_files:
            contracts = self.parser.parse_file(sol_file)
            contracts_count += len(contracts)
            for contract in contracts:
                all_findings.extend(self.analyze_contract(contract))
                if contract.storage_layout.total_slots > 0:
                    all_layouts.append(contract.storage_layout)
                for struct in contract.structs:
                    if struct.storage_layout.total_slots > 0:
                        all_layouts.append(struct.storage_layout)

        all_findings.sort(
            key=lambda f: (
                f.location.file_path,
                f.location.line,
                -f.severity.rank,
                f.rule_id,
            )
        )

        return ScanReport(
            target_path=str(target),
            files_scanned=len(sol_files),
            contracts_scanned=contracts_count,
            findings=all_findings,
            storage_layouts=all_layouts,
        )
