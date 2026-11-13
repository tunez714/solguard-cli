"""Defensive smart-contract security lint rules (SG001, SG002, SG003)."""

from __future__ import annotations

import re

from solguard.models import Category, Finding, FunctionDefinition, ParsedContract, Severity
from solguard.rules.base import BaseRule

_LOW_LEVEL_CALL_RE = re.compile(
    r"\.\s*(call|delegatecall|staticcall|send)\s*(?:\{[^}]*\})?\s*\("
)
_CHECKED_CALL_PREFIX_RE = re.compile(
    r"^(?:\(\s*bool\s+[A-Za-z_][A-Za-z0-9_]*|bool\s+[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*\s*=|\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,|require\s*\(|if\s*\(|assert\s*\()"
)

_EXTERNAL_INTERACTION_RE = re.compile(
    r"\.\s*(call|delegatecall|send|transfer)\s*(?:\{[^}]*\})?\s*\("
)
_REENTRANCY_GUARD_MODIFIERS = {
    "nonreentrant",
    "noreentrancy",
    "reentrancyguard",
    "lock",
    "mutex",
}

_TX_ORIGIN_AUTH_RE = re.compile(
    r"(?:\brequire\s*\([^;]*\btx\.origin\b|\bif\s*\([^)]*\btx\.origin\b|\btx\.origin\s*(?:==|!=)|(?:==|!=)\s*tx\.origin\b)"
)


class SG001UncheckedCallRule(BaseRule):
    """SG001: Unchecked return value of low-level `.call`, `.delegatecall`, `.staticcall`, or `.send`."""

    rule_id = "SG001"
    title = "Unchecked Low-Level Call Return Value"
    severity = Severity.HIGH
    category = Category.SECURITY
    description = (
        "Low-level EVM calls (.call, .delegatecall, .staticcall, .send) do not revert automatically "
        "when execution fails; instead they return a boolean `false`. Ignoring the return value can "
        "cause the contract to continue execution under the false assumption that a transfer or call succeeded."
    )
    remediation = (
        "Capture the boolean return value (e.g., `(bool success, ) = recipient.call{value: amount}(\"\");`) "
        "and verify it immediately with `require(success, \"Call failed\");`."
    )

    def analyze(self, contract: ParsedContract) -> list[Finding]:
        findings: list[Finding] = []
        if contract.kind == "interface":
            return findings

        for func in contract.functions:
            for stmt in func.body_lines:
                code = stmt.stripped
                if not code:
                    continue
                match = _LOW_LEVEL_CALL_RE.search(code)
                if not match:
                    continue

                call_kind = match.group(1)
                if _CHECKED_CALL_PREFIX_RE.search(code):
                    continue

                findings.append(
                    self.make_finding(
                        contract=contract,
                        line=stmt.line,
                        function_name=func.name,
                        snippet=stmt.raw,
                        message=(
                            f"Return value of low-level `.{call_kind}(...)` in `{contract.name}.{func.name}` "
                            "is ignored; execution continues silently if the sub-call reverts."
                        ),
                        metadata={"call_type": call_kind, "function": func.name},
                    )
                )

        return findings


def _mutates_state_variable(line_code: str, state_var_names: set[str]) -> str | None:
    """Return the mutated state variable name if `line_code` writes to a contract state variable."""
    if not line_code or not state_var_names:
        return None

    for var_name in sorted(state_var_names):
        # Match `var =`, `var[...] =`, `var.field =`, `var +=`, `var -=`, `var++`, `var--`, `delete var`
        assign_pattern = re.compile(
            rf"(?:^\s*|\bdelete\s+)\b{re.escape(var_name)}\b"
            rf"(?:\s*\[[^\]]+\]|\s*\.[A-Za-z_][A-Za-z0-9_]*)*"
            rf"(?:\s*(?:\+=|-=|\*=|/=|=[^=]|\+\+|--)|\b)"
        )
        if line_code.startswith(f"delete {var_name}"):
            return var_name
        match = assign_pattern.search(line_code)
        if match and any(
            op in line_code for op in ("=", "+=", "-=", "*=", "/=", "++", "--")
        ):
            # Ensure it's not a comparison `==`, `!=`, `<=`, `>=` before any assignment
            lhs_check = re.search(
                rf"\b{re.escape(var_name)}\b(?:\s*\[[^\]]*\]|\s*\.[A-Za-z_][A-Za-z0-9_]*)*\s*(\+=|-=|\*=|/=|\+\+|--|=(?!=))",
                line_code,
            )
            if lhs_check:
                return var_name
    return None


class SG002ReentrancyStateWriteRule(BaseRule):
    """SG002: State variable write after external call (Checks-Effects-Interactions violation)."""

    rule_id = "SG002"
    title = "State Write After External Call (CEI Violation)"
    severity = Severity.HIGH
    category = Category.SECURITY
    description = (
        "Mutating contract storage after performing an external call violates the "
        "Checks-Effects-Interactions (CEI) pattern and exposes the contract to reentrancy "
        "if the callee re-enters before balances or state flags are updated."
    )
    remediation = (
        "Update all state variables before invoking external calls (Checks-Effects-Interactions) "
        "or protect the function with a `nonReentrant` mutex modifier."
    )

    def _has_reentrancy_guard(self, func: FunctionDefinition) -> bool:
        return any(
            mod.lower() in _REENTRANCY_GUARD_MODIFIERS for mod in func.modifiers
        )

    def analyze(self, contract: ParsedContract) -> list[Finding]:
        findings: list[Finding] = []
        if contract.kind == "interface":
            return findings

        state_vars = contract.state_variable_names
        if not state_vars:
            return findings

        for func in contract.functions:
            if func.mutability in {"view", "pure"} or self._has_reentrancy_guard(func):
                continue

            external_call_line: int | None = None
            external_call_type: str | None = None

            for stmt in func.body_lines:
                code = stmt.stripped
                if not code:
                    continue

                ext_match = _EXTERNAL_INTERACTION_RE.search(code)
                if ext_match and external_call_line is None:
                    external_call_line = stmt.line
                    external_call_type = ext_match.group(1)
                    continue

                if external_call_line is not None:
                    mutated_var = _mutates_state_variable(code, state_vars)
                    if mutated_var is not None:
                        findings.append(
                            self.make_finding(
                                contract=contract,
                                line=stmt.line,
                                function_name=func.name,
                                snippet=stmt.raw,
                                message=(
                                    f"State variable `{mutated_var}` is written on line {stmt.line} after "
                                    f"external `.{external_call_type}` call on line {external_call_line} in "
                                    f"`{contract.name}.{func.name}` (violates Checks-Effects-Interactions)."
                                ),
                                metadata={
                                    "state_variable": mutated_var,
                                    "external_call_line": external_call_line,
                                    "function": func.name,
                                },
                            )
                        )

        return findings


class SG003TxOriginAuthRule(BaseRule):
    """SG003: Usage of `tx.origin` for authorization checks."""

    rule_id = "SG003"
    title = "Dangerous tx.origin Authorization Check"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    description = (
        "`tx.origin` returns the original EOA that initiated the transaction chain rather than "
        "the immediate caller (`msg.sender`). Relying on `tx.origin` for authorization allows "
        "any intermediate contract called by the user to impersonate their privileges."
    )
    remediation = (
        "Replace `tx.origin` with `msg.sender` for all access-control and authentication checks."
    )

    def analyze(self, contract: ParsedContract) -> list[Finding]:
        findings: list[Finding] = []
        if contract.kind == "interface":
            return findings

        for func in contract.functions:
            for stmt in func.body_lines:
                code = stmt.stripped
                if not code or "tx.origin" not in code:
                    continue
                if _TX_ORIGIN_AUTH_RE.search(code):
                    findings.append(
                        self.make_finding(
                            contract=contract,
                            line=stmt.line,
                            function_name=func.name,
                            snippet=stmt.raw,
                            message=(
                                f"`tx.origin` used for authorization in `{contract.name}.{func.name}`; "
                                "use `msg.sender` to authenticate the immediate caller."
                            ),
                            metadata={"function": func.name},
                        )
                    )

        return findings
