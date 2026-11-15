"""Unit tests for gas optimization and event indexing rules SG004 and SG005."""

from __future__ import annotations

from pathlib import Path

from solguard.engine import AnalyzerEngine
from solguard.models import Severity
from solguard.parser import parse_solidity_source
from solguard.rules import SG004UnindexedEventRule, SG005GasOptimizationRule


def test_sg004_flags_unindexed_event_parameters() -> None:
    source = """
    pragma solidity ^0.8.20;
    contract TokenEvents {
        event Transfer(address from, address to, uint256 value);
        event FullyIndexed(address indexed a, address indexed b, uint256 indexed c, bytes extraData);
    }
    """
    contract = parse_solidity_source(source)[0]
    findings = SG004UnindexedEventRule().analyze(contract)
    assert len(findings) == 1
    assert findings[0].rule_id == "SG004"
    assert findings[0].severity == Severity.LOW
    assert findings[0].metadata["event"] == "Transfer"
    assert findings[0].metadata["candidate_parameters"] == ["from", "to", "value"]


def test_sg005_flags_struct_packing_and_state_variable_packing() -> None:
    source = """
    pragma solidity ^0.8.20;
    contract UnpackedStorage {
        uint8 public flagA;
        uint256 public bigValue;
        uint8 public flagB;

        struct UserInfo {
            bool active;
            uint256 balance;
            address delegate;
        }
    }
    """
    contract = parse_solidity_source(source)[0]
    findings = SG005GasOptimizationRule().analyze(contract)
    kinds = {f.metadata["optimization_kind"] for f in findings}
    assert "struct_packing" in kinds
    assert "state_variable_packing" in kinds


def test_sg005_flags_readonly_memory_in_external_function_only() -> None:
    source = """
    pragma solidity ^0.8.20;
    contract CalldataCheck {
        // Should be flagged: external + memory + never mutated
        function hashLabels(string memory label, uint256[] memory values) external pure returns (uint256) {
            return bytes(label).length + values.length;
        }

        // Should NOT be flagged: mutated in-place
        function mutateArray(uint256[] memory values) external pure returns (uint256) {
            values[0] = 42;
            return values[0];
        }

        // Should NOT be flagged: public function (may be called internally with memory)
        function publicHelper(string memory label) public pure returns (uint256) {
            return bytes(label).length;
        }
    }
    """
    contract = parse_solidity_source(source)[0]
    findings = SG005GasOptimizationRule().analyze(contract)
    calldata_findings = [
        f for f in findings if f.metadata.get("optimization_kind") == "calldata_parameter"
    ]
    assert len(calldata_findings) == 2
    params = {f.metadata["parameter"] for f in calldata_findings}
    assert params == {"label", "values"}


def test_gas_inefficient_fixture_triggers_sg004_and_sg005(
    gas_inefficient_path: Path,
) -> None:
    report = AnalyzerEngine().scan_path(gas_inefficient_path)
    rule_ids = {f.rule_id for f in report.findings}
    assert "SG004" in rule_ids
    assert "SG005" in rule_ids


def test_clean_vault_fixture_has_zero_findings(clean_vault_path: Path) -> None:
    report = AnalyzerEngine().scan_path(clean_vault_path)
    assert report.findings == []
