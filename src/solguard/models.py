"""Core domain models, AST representations, and EVM type sizing utilities."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity level for static analysis findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        ranks = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
        }
        return ranks[self]

    @property
    def sarif_level(self) -> str:
        levels = {
            Severity.LOW: "note",
            Severity.MEDIUM: "warning",
            Severity.HIGH: "error",
        }
        return levels[self]

    def meets_threshold(self, threshold: Severity) -> bool:
        return self.rank >= threshold.rank

    @classmethod
    def from_str(cls, value: str) -> Severity:
        normalized = value.strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"Unsupported severity '{value}'. Expected one of: low, medium, high.")


class Category(str, Enum):
    """Rule classification category."""

    SECURITY = "security"
    GAS = "gas"
    BEST_PRACTICE = "best-practice"


_UINT_INT_RE = re.compile(r"^u?int(\d+)?$")
_BYTES_FIXED_RE = re.compile(r"^bytes(\d+)$")
_FIXED_ARRAY_RE = re.compile(r"^(.+)\[(\d+)\]$")


def evm_type_bytes(type_name: str) -> int:
    """Return the EVM storage size in bytes (1..32) for a Solidity type.

    Dynamic types (mappings, dynamic arrays, strings, bytes) and structs
    consume a full 32-byte storage slot boundary.
    """
    cleaned = " ".join(type_name.strip().split())
    if cleaned.endswith(" payable"):
        cleaned = cleaned[: -len(" payable")].strip()

    if cleaned.startswith("mapping") or cleaned.endswith("[]") or cleaned in {"bytes", "string"}:
        return 32

    fixed_arr = _FIXED_ARRAY_RE.match(cleaned)
    if fixed_arr:
        return 32

    if cleaned == "bool":
        return 1

    if cleaned == "address":
        return 20

    int_match = _UINT_INT_RE.match(cleaned)
    if int_match:
        bits_str = int_match.group(1)
        if not bits_str:
            return 32
        bits = int(bits_str)
        if 8 <= bits <= 256 and bits % 8 == 0:
            return bits // 8
        return 32

    bytes_match = _BYTES_FIXED_RE.match(cleaned)
    if bytes_match:
        size = int(bytes_match.group(1))
        if 1 <= size <= 32:
            return size
        return 32

    # Default for structs or external contract types unknown at single-pass level
    return 32


def is_packable_type(type_name: str) -> bool:
    """Return True if the type can be packed with adjacent fields in a 32-byte EVM slot."""
    cleaned = type_name.strip()
    if cleaned.startswith("mapping") or "[" in cleaned or cleaned in {"bytes", "string"}:
        return False
    return evm_type_bytes(cleaned) < 32


def is_reference_type(type_name: str) -> bool:
    """Return True if the parameter type requires a data location (memory/calldata/storage)."""
    cleaned = type_name.strip()
    if cleaned in {"string", "bytes"}:
        return True
    if "[" in cleaned and "]" in cleaned:
        return True
    # Custom struct types start with an uppercase letter and are not elementary types
    if cleaned and cleaned[0].isupper() and not cleaned.startswith(("IERC", "ERC")):
        return True
    return False


def is_filterable_event_type(type_name: str) -> bool:
    """Return True if an event parameter is a value type commonly indexed for off-chain filtering."""
    cleaned = type_name.strip()
    if cleaned in {"address", "bool"}:
        return True
    if _UINT_INT_RE.match(cleaned) or _BYTES_FIXED_RE.match(cleaned):
        return True
    return False


@dataclass(frozen=True)
class SourceLocation:
    """Line and column coordinates in a Solidity source file."""

    file_path: str
    line: int
    column: int = 1
    end_line: int | None = None
    end_column: int | None = None
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line or self.line,
            "end_column": self.end_column or self.column,
            "snippet": self.snippet,
        }


@dataclass(frozen=True)
class PragmaDirective:
    """Parsed `pragma solidity ...;` directive."""

    raw: str
    version_constraint: str
    line: int
    is_floating: bool


@dataclass
class StateVariable:
    """Contract-level state variable declaration."""

    name: str
    type_name: str
    visibility: str
    is_constant: bool
    is_immutable: bool
    line: int
    column: int
    byte_size: int
    slot_index: int | None = None
    byte_offset: int | None = None


@dataclass(frozen=True)
class StorageSlotItem:
    """Single variable or struct member placed inside a 32-byte EVM storage slot."""

    name: str
    type_name: str
    byte_size: int
    byte_offset: int
    line: int


@dataclass
class StorageSlot:
    """32-byte EVM storage slot (256 bits) containing one or more packed items."""

    slot_index: int
    items: list[StorageSlotItem] = field(default_factory=list)

    @property
    def used_bytes(self) -> int:
        return sum(item.byte_size for item in self.items)

    @property
    def free_bytes(self) -> int:
        return max(0, 32 - self.used_bytes)


@dataclass
class StorageLayout:
    """Computed EVM storage slot layout and optimal packing analysis."""

    target_name: str
    kind: str  # "contract" or "struct"
    line: int
    slots: list[StorageSlot]
    total_slots: int
    optimal_slots: int
    optimal_order: list[str]
    estimated_gas_saved: int

    @property
    def slots_saved(self) -> int:
        return max(0, self.total_slots - self.optimal_slots)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "kind": self.kind,
            "line": self.line,
            "total_slots": self.total_slots,
            "optimal_slots": self.optimal_slots,
            "slots_saved": self.slots_saved,
            "estimated_gas_saved": self.estimated_gas_saved,
            "optimal_order": self.optimal_order,
            "slots": [
                {
                    "slot_index": slot.slot_index,
                    "used_bytes": slot.used_bytes,
                    "free_bytes": slot.free_bytes,
                    "items": [
                        {
                            "name": item.name,
                            "type": item.type_name,
                            "bytes": item.byte_size,
                            "offset": item.byte_offset,
                            "line": item.line,
                        }
                        for item in slot.items
                    ],
                }
                for slot in self.slots
            ],
        }


@dataclass(frozen=True)
class StructField:
    """Field inside a Solidity `struct` declaration."""

    name: str
    type_name: str
    byte_size: int
    line: int
    column: int = 1


@dataclass
class StructDefinition:
    """Parsed Solidity `struct` declaration and its storage packing layout."""

    name: str
    line: int
    end_line: int
    fields: list[StructField]
    storage_layout: StorageLayout


@dataclass(frozen=True)
class EventParameter:
    """Parameter inside an `event` declaration."""

    name: str
    type_name: str
    indexed: bool


@dataclass(frozen=True)
class EventDefinition:
    """Parsed Solidity `event` declaration."""

    name: str
    line: int
    parameters: list[EventParameter]
    raw_signature: str

    @property
    def indexed_count(self) -> int:
        return sum(1 for param in self.parameters if param.indexed)


@dataclass(frozen=True)
class FunctionParameter:
    """Parameter or return parameter of a Solidity function."""

    name: str
    type_name: str
    data_location: str | None = None


@dataclass(frozen=True)
class StatementInfo:
    """Single source line inside a function body."""

    line: int
    raw: str
    stripped: str


@dataclass
class FunctionDefinition:
    """Parsed Solidity function, constructor, fallback, or receive definition."""

    name: str
    kind: str  # "function", "constructor", "fallback", "receive"
    visibility: str
    mutability: str  # "nonpayable", "payable", "view", "pure"
    modifiers: list[str]
    parameters: list[FunctionParameter]
    return_parameters: list[FunctionParameter]
    line: int
    end_line: int
    body_lines: list[StatementInfo]
    raw_body: str


@dataclass
class ParsedContract:
    """Complete static analysis representation of a Solidity contract, library, or interface."""

    name: str
    kind: str  # "contract", "abstract contract", "library", "interface"
    file_path: str
    line: int
    end_line: int
    base_contracts: list[str]
    pragmas: list[PragmaDirective]
    state_variables: list[StateVariable]
    structs: list[StructDefinition]
    events: list[EventDefinition]
    functions: list[FunctionDefinition]
    storage_layout: StorageLayout
    raw_source: str
    suppressed_lines: dict[int, set[str]] = field(default_factory=dict)

    @property
    def state_variable_names(self) -> set[str]:
        return {
            var.name
            for var in self.state_variables
            if not var.is_constant and not var.is_immutable
        }


@dataclass(frozen=True)
class Finding:
    """Single lint or security diagnostic produced by a rule."""

    rule_id: str
    title: str
    severity: Severity
    category: Category
    message: str
    remediation: str
    contract_name: str
    location: SourceLocation
    function_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "message": self.message,
            "remediation": self.remediation,
            "contract_name": self.contract_name,
            "function_name": self.function_name,
            "location": self.location.to_dict(),
            "metadata": self.metadata,
        }


@dataclass
class ScanReport:
    """Aggregated report across all scanned Solidity files and contracts."""

    target_path: str
    files_scanned: int
    contracts_scanned: int
    findings: list[Finding] = field(default_factory=list)
    storage_layouts: list[StorageLayout] = field(default_factory=list)

    def count_by_severity(self) -> dict[str, int]:
        counts = {
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
        }
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def should_fail(self, fail_on: Severity | None) -> bool:
        if fail_on is None:
            return False
        return any(f.severity.meets_threshold(fail_on) for f in self.findings)
