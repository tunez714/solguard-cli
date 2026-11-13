"""Rule registry and exports for solguard static analysis checks."""

from __future__ import annotations

from solguard.rules.base import BaseRule
from solguard.rules.gas import SG004UnindexedEventRule, SG005GasOptimizationRule
from solguard.rules.security import (
    SG001UncheckedCallRule,
    SG002ReentrancyStateWriteRule,
    SG003TxOriginAuthRule,
)

RULE_CLASSES: tuple[type[BaseRule], ...] = (
    SG001UncheckedCallRule,
    SG002ReentrancyStateWriteRule,
    SG003TxOriginAuthRule,
    SG004UnindexedEventRule,
    SG005GasOptimizationRule,
)


def get_all_rules() -> list[BaseRule]:
    """Instantiate and return all built-in static analysis rules in canonical order."""
    return [cls() for cls in RULE_CLASSES]


def get_rule_by_id(rule_id: str) -> BaseRule:
    """Lookup a single rule instance by its ID (e.g., `SG001`)."""
    normalized = rule_id.strip().upper()
    for cls in RULE_CLASSES:
        if cls.rule_id == normalized:
            return cls()
    valid = ", ".join(cls.rule_id for cls in RULE_CLASSES)
    raise KeyError(f"Unknown rule ID '{rule_id}'. Available rules: {valid}")


__all__ = [
    "BaseRule",
    "RULE_CLASSES",
    "SG001UncheckedCallRule",
    "SG002ReentrancyStateWriteRule",
    "SG003TxOriginAuthRule",
    "SG004UnindexedEventRule",
    "SG005GasOptimizationRule",
    "get_all_rules",
    "get_rule_by_id",
]
