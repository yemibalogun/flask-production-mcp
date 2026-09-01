"""Shared utilities used by production-readiness analyzers."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable

from flask_production_mcp.models.findings import (
    AuditResult,
    AuditSummary,
    Finding,
    Severity,
)

# The score starts at 100 and deductions are applied for findings.
#
# These values are intentionally conservative for now. Later we can make
# scoring category-aware and introduce confidence-based adjustments.
SEVERITY_PENALTIES: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


def build_summary(findings: Iterable[Finding]) -> AuditSummary:
    """Build a severity summary from findings."""

    counts = Counter(finding.severity for finding in findings)

    return AuditSummary(
        critical=counts.get(Severity.CRITICAL, 0),
        high=counts.get(Severity.HIGH, 0),
        medium=counts.get(Severity.MEDIUM, 0),
        low=counts.get(Severity.LOW, 0),
        info=counts.get(Severity.INFO, 0),
    )


def calculate_score(findings: Iterable[Finding]) -> int:
    """Calculate a production-readiness score between 0 and 100."""

    penalty = sum(
        SEVERITY_PENALTIES.get(finding.severity, 0)
        for finding in findings
    )

    return max(0, 100 - penalty)


def is_python_file(path: Path) -> bool:
    """Return True when the supplied path is a Python source file."""

    return path.is_file() and path.suffix.lower() == ".py"


def recommendations_from_findings(
    findings: Iterable[Finding],
) -> list[str]:
    """Collect unique, order-preserving recommendations from findings."""

    return list(
        dict.fromkeys(
            finding.recommendation
            for finding in findings
            if finding.recommendation
            and finding.severity is not Severity.INFO
        )
    )


def build_audit_result(
    project_path: str | Path,
    findings: Iterable[Finding],
    errors: Iterable[str] | None = None,
) -> AuditResult:
    """
    Assemble a standard :class:`AuditResult` from analyzer findings.

    Every analyzer-backed MCP tool returns this same shape so an agent can
    consume any audit response without special-casing the tool.
    """

    findings = list(findings)

    return AuditResult(
        success=True,
        project_path=str(project_path),
        score=calculate_score(findings),
        findings=findings,
        summary=build_summary(findings),
        recommendations=recommendations_from_findings(findings),
        errors=list(errors or []),
    )