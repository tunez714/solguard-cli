"""Base rule abstraction for solguard static analysis rules."""

from __future__ import annotations

from abc import ABC, abstractmethod

from solguard.models import Category, Finding, ParsedContract, Severity, SourceLocation


class BaseRule(ABC):
    """Abstract base class implemented by all security and gas rules."""

    rule_id: str
    title: str
    severity: Severity
    category: Category
    description: str
    remediation: str

    @abstractmethod
    def analyze(self, contract: ParsedContract) -> list[Finding]:
        """Inspect a parsed contract and return any findings."""

    def make_finding(
        self,
        contract: ParsedContract,
        line: int,
        message: str,
        snippet: str = "",
        function_name: str | None = None,
        column: int = 1,
        metadata: dict | None = None,
    ) -> Finding:
        """Helper to construct a standardized `Finding` instance."""
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            category=self.category,
            message=message,
            remediation=self.remediation,
            contract_name=contract.name,
            function_name=function_name,
            location=SourceLocation(
                file_path=contract.file_path,
                line=line,
                column=column,
                end_line=line,
                end_column=max(column, len(snippet.rstrip()) + 1),
                snippet=snippet.strip(),
            ),
            metadata=metadata or {},
        )
