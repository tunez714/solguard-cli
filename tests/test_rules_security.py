"""Unit tests for security rules SG001, SG002, and SG003."""

from __future__ import annotations

from pathlib import Path

from solguard.engine import AnalyzerEngine
from solguard.models import Severity
from solguard.parser import parse_solidity_source
from solguard.rules import (
    SG001UncheckedCallRule,
    SG002ReentrancyStateWriteRule,
    SG003TxOriginAuthRule,
)


def test_sg001_detects_unchecked_low_level_calls() -> None:
    source = """
    pragma solidity ^0.8.20;
    contract Payout {
        function unsafePay(address payable to, uint256 amt) external {
            to.call{value: amt}("");
            to.send(amt);
        }
    }
    """
    contract = parse_solidity_source(source)[0]
    findings = SG001UncheckedCallRule().analyze(contract)
    assert len(findings) == 2
    assert all(f.rule_id == "SG001" for f in findings)
    assert all(f.severity == Severity.HIGH for f in findings)


def test_sg001_allows_checked_calls() -> None:
    source = """
    pragma solidity ^0.8.20;
    contract SafePayout {
        function safePay(address payable to, uint256 amt) external {
            (bool success, ) = to.call{value: amt}("");
            require(success, "Failed");
            require(to.send(amt), "Send failed");
        }
    }
    """
    contract = parse_solidity_source(source)[0]
    findings = SG001UncheckedCallRule().analyze(contract)
    assert findings == []


def test_sg002_detects_state_write_after_external_call() -> None:
    source = """
    pragma solidity ^0.8.20;
    contract ReentrantPool {
        mapping(address => uint256) public shares;
        uint256 public totalShares;

        function withdraw(uint256 amount) external {
            require(shares[msg.sender] >= amount, "Low shares");
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok, "Fail");
            shares[msg.sender] -= amount;
            totalShares -= amount;
        }
    }
    """
    contract = parse_solidity_source(source)[0]
    findings = SG002ReentrancyStateWriteRule().analyze(contract)
    assert len(findings) == 2
    assert findings[0].rule_id == "SG002"
    assert findings[0].metadata["state_variable"] == "shares"
    assert findings[1].metadata["state_variable"] == "totalShares"


def test_sg002_respects_non_reentrant_modifier_and_cei_order() -> None:
    source = """
    pragma solidity ^0.8.20;
    contract GuardedPool {
        mapping(address => uint256) public shares;

        function withdrawGuarded(uint256 amount) external nonReentrant {
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok, "Fail");
            shares[msg.sender] -= amount;
        }

        function withdrawCEI(uint256 amount) external {
            shares[msg.sender] -= amount;
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok, "Fail");
        }
    }
    """
    contract = parse_solidity_source(source)[0]
    findings = SG002ReentrancyStateWriteRule().analyze(contract)
    assert findings == []


def test_sg003_detects_tx_origin_authorization() -> None:
    source = """
    pragma solidity ^0.8.20;
    contract LegacyAuth {
        address public admin;
        function setAdmin(address next) external {
            require(tx.origin == admin, "Only admin");
            admin = next;
        }
    }
    """
    contract = parse_solidity_source(source)[0]
    findings = SG003TxOriginAuthRule().analyze(contract)
    assert len(findings) == 1
    assert findings[0].rule_id == "SG003"
    assert findings[0].severity == Severity.MEDIUM


def test_inline_suppression_filters_security_findings() -> None:
    source = """
    pragma solidity ^0.8.20;
    contract Suppressed {
        address public owner;
        function ping(address target) external {
            // solguard-disable-next-line SG003
            require(tx.origin == owner, "Origin check");
            target.call(""); // solguard-disable-line SG001
        }
    }
    """
    report = AnalyzerEngine().scan_source(source)
    assert report.findings == []


def test_vulnerable_vault_fixture_triggers_sg001_sg002_sg003(
    vulnerable_vault_path: Path,
) -> None:
    report = AnalyzerEngine().scan_path(vulnerable_vault_path)
    rule_ids = {f.rule_id for f in report.findings}
    assert {"SG001", "SG002", "SG003"}.issubset(rule_ids)
