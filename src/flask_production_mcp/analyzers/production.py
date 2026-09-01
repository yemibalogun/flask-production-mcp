"""Unified production-readiness audit for Flask applications.

This orchestrator runs every individual analyzer (Flask architecture,
security, database, code quality), then aggregates their findings into a
single production-readiness assessment with a per-category breakdown.

The target Flask application is never imported or executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.base import (
    build_summary,
    calculate_score,
)
from flask_production_mcp.analyzers.code_quality import (
    analyze_code_quality_file,
)
from flask_production_mcp.analyzers.database import analyze_database
from flask_production_mcp.analyzers.exclusions import iter_python_files
from flask_production_mcp.analyzers.flask import analyze_flask
from flask_production_mcp.analyzers.security import analyze_security
from flask_production_mcp.models.findings import Finding, Severity

# A project is only considered production ready when its overall score is at
# or above this threshold and it has no critical or high-severity findings.
PRODUCTION_READY_SCORE_THRESHOLD = 70

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_BLOCKER_SEVERITIES = (Severity.CRITICAL, Severity.HIGH)
_RECOMMENDATION_SEVERITIES = (Severity.LOW, Severity.INFO)


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    """Order findings by severity, then category, then location."""

    return sorted(
        findings,
        key=lambda finding: (
            _SEVERITY_RANK.get(finding.severity, 99),
            finding.category,
            finding.file or "",
            finding.line or 0,
        ),
    )


def _run_flask(root: Path, errors: list[str]) -> list[Finding]:
    try:
        return list(analyze_flask(root).findings)
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"Flask analyzer failed: {exc}")
        return []


def _run_security(root: Path, errors: list[str]) -> list[Finding]:
    try:
        result = analyze_security(root)
        errors.extend(result.errors)
        return list(result.findings)
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"Security analyzer failed: {exc}")
        return []


def _run_database(root: Path, errors: list[str]) -> list[Finding]:
    try:
        result = analyze_database(root)
        for parse_error in result.get("parse_errors", []):
            errors.append(
                f"{parse_error.get('file')}: {parse_error.get('error')}"
            )
        return list(result.get("findings", []))
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"Database analyzer failed: {exc}")
        return []


def _run_code_quality(root: Path, errors: list[str]) -> list[Finding]:
    try:
        findings: list[Finding] = []
        for file_path in iter_python_files(root, include_tests=False):
            findings.extend(analyze_code_quality_file(file_path))
        return findings
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"Code-quality analyzer failed: {exc}")
        return []


def analyze_production(project_path: str | Path) -> dict[str, Any]:
    """Run every analyzer and return an aggregated production assessment."""

    root = Path(project_path).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Project path does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Project path is not a directory: {root}")

    errors: list[str] = []

    category_findings: dict[str, list[Finding]] = {
        "flask": _run_flask(root, errors),
        "security": _run_security(root, errors),
        "database": _run_database(root, errors),
        "code_quality": _run_code_quality(root, errors),
    }

    all_findings = [
        finding
        for findings in category_findings.values()
        for finding in findings
    ]

    categories = {
        name: {
            "score": calculate_score(findings),
            "summary": build_summary(findings).model_dump(),
            "finding_count": len(findings),
        }
        for name, findings in category_findings.items()
    }

    overall_summary = build_summary(all_findings)
    overall_score = calculate_score(all_findings)

    blocking_reasons: list[str] = []
    if overall_summary.critical:
        blocking_reasons.append(
            f"{overall_summary.critical} critical finding(s)"
        )
    if overall_summary.high:
        blocking_reasons.append(
            f"{overall_summary.high} high-severity finding(s)"
        )
    if overall_score < PRODUCTION_READY_SCORE_THRESHOLD:
        blocking_reasons.append(
            f"overall score {overall_score} is below the production "
            f"threshold of {PRODUCTION_READY_SCORE_THRESHOLD}"
        )

    blockers = _sort_findings(
        [f for f in all_findings if f.severity in _BLOCKER_SEVERITIES]
    )
    warnings = _sort_findings(
        [f for f in all_findings if f.severity is Severity.MEDIUM]
    )
    recommendations = _sort_findings(
        [f for f in all_findings if f.severity in _RECOMMENDATION_SEVERITIES]
    )

    return {
        "success": True,
        "project_path": str(root),
        "overall_score": overall_score,
        "production_ready": not blocking_reasons,
        "blocking_reasons": blocking_reasons,
        "summary": overall_summary.model_dump(),
        "categories": categories,
        "blockers": [f.model_dump(mode="json") for f in blockers],
        "warnings": [f.model_dump(mode="json") for f in warnings],
        "recommendations": [
            f.model_dump(mode="json") for f in recommendations
        ],
        "errors": errors,
    }
