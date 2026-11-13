"""EVM event indexing and storage/calldata gas optimization rules (SG004, SG005)."""

from __future__ import annotations

import re

from solguard.models import (
    Category,
    Finding,
    FunctionDefinition,
    ParsedContract,
    Severity,
    is_filterable_event_type,
    is_reference_type,
)
from solguard.rules.base import BaseRule

MAX_INDEXED_EVENT_TOPICS = 3


class SG004UnindexedEventRule(BaseRule):
    """SG004: Event declaration missing `indexed` on filterable value-type parameters."""

    rule_id = "SG004"
    title = "Unindexed Filterable Event Parameters"
    severity = Severity.LOW
    category = Category.GAS
    description = (
        "Solidity events support up to three `indexed` parameters stored as EVM LOG topics. "
        "Leaving `address`, `uint*`, `bytes32`, or `bool` parameters unindexed when fewer than "
        "3 parameters are indexed forces full data-blob ABI encoding and prevents efficient "
        "Bloom-filter topic queries."
    )
    remediation = (
        "Add the `indexed` keyword to up to 3 filterable value-type parameters (prioritizing "
        "`address` and identifier `uint256`/`bytes32` fields)."
    )

    def analyze(self, contract: ParsedContract) -> list[Finding]:
        findings: list[Finding] = []
        raw_lines = contract.raw_source.splitlines()

        for event in contract.events:
            if event.indexed_count >= MAX_INDEXED_EVENT_TOPICS:
                continue

            remaining_slots = MAX_INDEXED_EVENT_TOPICS - event.indexed_count
            candidates = [
                param
                for param in event.parameters
                if not param.indexed and is_filterable_event_type(param.type_name)
            ]
            if not candidates:
                continue

            recommended = candidates[:remaining_slots]
            rec_names = ", ".join(
                f"`{p.type_name} indexed {p.name}`".strip() for p in recommended
            )
            snippet = (
                raw_lines[event.line - 1]
                if 1 <= event.line <= len(raw_lines)
                else event.raw_signature
            )

            findings.append(
                self.make_finding(
                    contract=contract,
                    line=event.line,
                    snippet=snippet,
                    message=(
                        f"Event `{event.name}` has {event.indexed_count}/{MAX_INDEXED_EVENT_TOPICS} indexed "
                        f"topics; mark {rec_names} as `indexed` to enable EVM topic filtering and reduce "
                        "unindexed log data."
                    ),
                    metadata={
                        "event": event.name,
                        "indexed_count": event.indexed_count,
                        "candidate_parameters": [p.name or p.type_name for p in recommended],
                    },
                )
            )

        return findings


def _is_parameter_mutated(func: FunctionDefinition, param_name: str) -> bool:
    """Return True if `param_name` is assigned or mutated inside `func`."""
    if not param_name:
        return False
    pattern = re.compile(
        rf"\b{re.escape(param_name)}\b(?:\s*\[[^\]]*\]|\s*\.[A-Za-z_][A-Za-z0-9_]*)*\s*(?:\+=|-=|\*=|/=|=[^=])"
    )
    for stmt in func.body_lines:
        if pattern.search(stmt.stripped):
            return True
    return False


class SG005GasOptimizationRule(BaseRule):
    """SG005: EVM 32-byte storage slot packing and `calldata` vs `memory` gas optimizations."""

    rule_id = "SG005"
    title = "EVM Storage Packing & Calldata Gas Optimization"
    severity = Severity.MEDIUM
    category = Category.GAS
    description = (
        "The EVM packs adjacent state variables and struct members that fit within a 32-byte (256-bit) "
        "storage slot into a single SSTORE/SLOAD operation. Poor field ordering wastes storage slots "
        "(~20,000 gas per new SSTORE and 2,100 gas per cold SLOAD). Additionally, read-only reference "
        "parameters in `external` functions declared as `memory` incur unnecessary ABI memory copies "
        "compared to `calldata`."
    )
    remediation = (
        "Group smaller value types (`uint128`, `uint64`, `uint32`, `uint8`, `bool`, `address`) "
        "contiguously so their byte sizes sum to <= 32 bytes per slot, and declare read-only "
        "array/bytes/string/struct parameters in `external` functions as `calldata`."
    )

    def analyze(self, contract: ParsedContract) -> list[Finding]:
        findings: list[Finding] = []
        if contract.kind == "interface":
            return findings

        raw_lines = contract.raw_source.splitlines()

        # 1. Check struct storage slot packing
        for struct in contract.structs:
            layout = struct.storage_layout
            if layout.slots_saved > 0:
                snippet = (
                    raw_lines[struct.line - 1]
                    if 1 <= struct.line <= len(raw_lines)
                    else f"struct {struct.name}"
                )
                order_str = ", ".join(layout.optimal_order)
                findings.append(
                    self.make_finding(
                        contract=contract,
                        line=struct.line,
                        snippet=snippet,
                        message=(
                            f"Struct `{contract.name}.{struct.name}` occupies {layout.total_slots} storage slots "
                            f"but can be tightly packed into {layout.optimal_slots} slot(s) "
                            f"(saving {layout.slots_saved} slot(s) / ~{layout.estimated_gas_saved:,} gas per write+read). "
                            f"Suggested field order: [{order_str}]."
                        ),
                        metadata={
                            "optimization_kind": "struct_packing",
                            "target": struct.name,
                            "current_slots": layout.total_slots,
                            "optimal_slots": layout.optimal_slots,
                            "slots_saved": layout.slots_saved,
                            "estimated_gas_saved": layout.estimated_gas_saved,
                            "optimal_order": layout.optimal_order,
                        },
                    )
                )

        # 2. Check contract-level state variable storage slot packing
        c_layout = contract.storage_layout
        if c_layout.slots_saved > 0:
            first_var_line = (
                contract.state_variables[0].line
                if contract.state_variables
                else contract.line
            )
            snippet = (
                raw_lines[first_var_line - 1]
                if 1 <= first_var_line <= len(raw_lines)
                else f"contract {contract.name}"
            )
            order_str = ", ".join(c_layout.optimal_order)
            findings.append(
                self.make_finding(
                    contract=contract,
                    line=first_var_line,
                    snippet=snippet,
                    message=(
                        f"State variables in `{contract.name}` occupy {c_layout.total_slots} storage slots "
                        f"but can be tightly packed into {c_layout.optimal_slots} slot(s) "
                        f"(saving {c_layout.slots_saved} slot(s) / ~{c_layout.estimated_gas_saved:,} gas). "
                        f"Suggested declaration order: [{order_str}]."
                    ),
                    metadata={
                        "optimization_kind": "state_variable_packing",
                        "target": contract.name,
                        "current_slots": c_layout.total_slots,
                        "optimal_slots": c_layout.optimal_slots,
                        "slots_saved": c_layout.slots_saved,
                        "estimated_gas_saved": c_layout.estimated_gas_saved,
                        "optimal_order": c_layout.optimal_order,
                    },
                )
            )

        # 3. Check external functions with read-only `memory` reference parameters
        for func in contract.functions:
            if func.visibility != "external":
                continue

            for param in func.parameters:
                if param.data_location != "memory":
                    continue
                if not is_reference_type(param.type_name):
                    continue
                if _is_parameter_mutated(func, param.name):
                    continue

                snippet = (
                    raw_lines[func.line - 1]
                    if 1 <= func.line <= len(raw_lines)
                    else f"function {func.name}"
                )
                param_label = f"{param.type_name} memory {param.name}".strip()
                findings.append(
                    self.make_finding(
                        contract=contract,
                        line=func.line,
                        function_name=func.name,
                        snippet=snippet,
                        message=(
                            f"Parameter `{param_label}` in external function `{contract.name}.{func.name}` "
                            "is never mutated; declare it as `calldata` instead of `memory` to avoid "
                            "expensive call-data-to-memory copying."
                        ),
                        metadata={
                            "optimization_kind": "calldata_parameter",
                            "function": func.name,
                            "parameter": param.name,
                            "type": param.type_name,
                        },
                    )
                )

        return findings
