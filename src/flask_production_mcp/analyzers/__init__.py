"""Shared functionality for production-readiness analyzers."""

from __future__ import annotations

from collections import Counter

from flask_production_mcp.models.findings import (
    AuditSummary,
    Finding,
    Severity,
)


# Higher severity findings receive larger deductions.
#
# These values are deliberately conservative. We can later introduce
# category-specific weighting and confidence levels without changing
# the public Finding model.
SEVERITY_PENALTIES: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


def build_summary(findings: list[Finding]) -> AuditSummary:
    """Build severity counters from audit findings."""

    counts = Counter(finding.severity for finding in findings)

    return AuditSummary(
        critical=counts.get(Severity.CRITICAL, 0),
        high=counts.get(Severity.HIGH, 0),
        medium=counts.get(Severity.MEDIUM, 0),
        low=counts.get(Severity.LOW, 0),
        info=counts.get(Severity.INFO, 0),
    )


def calculate_score(findings: list[Finding]) -> int:
    """Calculate a bounded production-readiness score."""

    # Start at 100 and deduct according to finding severity.
    #
    # We cap the result at zero so a project with many findings does not
    # produce confusing negative scores.
    penalty = sum(
        SEVERITY_PENALTIES.get(finding.severity, 0)
        for finding in findings
    )

    return max(0, 100 - penalty)