"""Pytest shared fixtures for solguard-cli test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture()
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture()
def vulnerable_vault_path() -> Path:
    return FIXTURES_DIR / "vulnerable_vault.sol"


@pytest.fixture()
def gas_inefficient_path() -> Path:
    return FIXTURES_DIR / "gas_inefficient.sol"


@pytest.fixture()
def clean_vault_path() -> Path:
    return FIXTURES_DIR / "clean_vault.sol"
