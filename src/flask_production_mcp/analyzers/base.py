"""Shared utilities used by production-readiness analyzers."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable

from flask_production_mcp.models.findings import (
    AuditResult,
    AuditSummary,
    Confidence,
    Finding,
    Severity,
)

# The score starts at 100 and deductions are applied for findings.
SEVERITY_PENALTIES: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

# Low-confidence findings are static-analysis guesses. They still count,
# but they must not tank a score or block a release on their own.
CONFIDENCE_WEIGHT: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.5,
    Confidence.LOW: 0.25,
}

_BLOCKER_SEVERITIES = frozenset({Severity.CRITICAL, Severity.HIGH})


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
    """Raw production-readiness score (0-100), severity-only penalties."""

    penalty = sum(
        SEVERITY_PENALTIES.get(finding.severity, 0)
        for finding in findings
    )

    return max(0, 100 - penalty)


def weighted_score(findings: Iterable[Finding]) -> int:
    """
    Confidence-weighted production-readiness score (0-100).

    A high-confidence finding costs its full severity penalty; medium and
    low confidence cost proportionally less. This keeps a long tail of
    "consider an index"-style guesses from collapsing the score while a
    confirmed critical still bites hard.
    """

    penalty = sum(
        SEVERITY_PENALTIES.get(finding.severity, 0)
        * CONFIDENCE_WEIGHT.get(finding.confidence, 1.0)
        for finding in findings
    )

    return max(0, round(100 - penalty))


def is_blocker(finding: Finding) -> bool:
    """A blocker is a high-confidence critical/high-severity finding."""

    return (
        finding.severity in _BLOCKER_SEVERITIES
        and finding.confidence is Confidence.HIGH
    )


def classify_findings(
    findings: Iterable[Finding],
) -> tuple[list[Finding], list[Finding], list[Finding]]:
    """
    Split findings into (blockers, advisories, notes).

    - blockers  : high-confidence critical/high - these gate a release
    - advisories: everything else at critical/high/medium severity -
                  real, but needs a human judgement call
    - notes     : low / info severity cleanups
    """

    blockers: list[Finding] = []
    advisories: list[Finding] = []
    notes: list[Finding] = []

    for finding in findings:
        if is_blocker(finding):
            blockers.append(finding)
        elif finding.severity in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
        ):
            advisories.append(finding)
        else:
            notes.append(finding)

    return blockers, advisories, notes


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
        score=weighted_score(findings),
        findings=findings,
        summary=build_summary(findings),
        recommendations=recommendations_from_findings(findings),
        errors=list(errors or []),
    )
