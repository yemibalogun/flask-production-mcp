"""Unified production-readiness audit for Flask applications.

This orchestrator runs every individual analyzer (Flask architecture,
templates, security, database, code quality), then aggregates their
findings into a single assessment with a per-category breakdown.

Findings are split into three tiers so a long tail of low-confidence
guesses never blocks a release:

- blockers   : high-confidence critical/high severity - these gate ready
- advisories : other critical/high/medium findings - human judgement
- notes      : low / info cleanups

The target Flask application is never imported or executed.
"""

from __future__ import annotations

from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.architecture import analyze_architecture
from flask_production_mcp.analyzers.base import (
    build_summary,
    classify_findings,
    weighted_score,
)
from flask_production_mcp.analyzers.code_quality import (
    analyze_code_quality_file,
)
from flask_production_mcp.analyzers.database import analyze_database
from flask_production_mcp.analyzers.dependencies import analyze_dependencies
from flask_production_mcp.analyzers.deployment import analyze_deployment
from flask_production_mcp.analyzers.exclusions import iter_python_files
from flask_production_mcp.analyzers.flask import (
    analyze_flask,
    discover_flask_project,
)
from flask_production_mcp.analyzers.security import analyze_security
from flask_production_mcp.analyzers.templates import analyze_templates
from flask_production_mcp.config import Config
from flask_production_mcp.models.findings import Finding, Severity

# A category whose confidence-weighted score falls below this floor blocks
# a release even without an individual high-confidence blocker, because a
# pile of medium-confidence problems in one area is itself a red flag.
CATEGORY_SCORE_FLOOR = 50

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


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


def _run_architecture(root: Path, errors: list[str]) -> list[Finding]:
    try:
        return list(analyze_architecture(root))
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"Architecture analyzer failed: {exc}")
        return []


def _run_deployment(root: Path, errors: list[str]) -> list[Finding]:
    try:
        return list(analyze_deployment(root))
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"Deployment analyzer failed: {exc}")
        return []


def _known_endpoints(root: Path, errors: list[str]) -> set[str]:
    try:
        architecture = discover_flask_project(str(root)).get(
            "flask_architecture", {}
        )
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"Route discovery failed: {exc}")
        return set()

    endpoints: set[str] = {"static"}
    for route in architecture.get("routes", []):
        endpoint = route.get("endpoint")
        blueprint = route.get("blueprint")
        if endpoint:
            endpoints.add(
                f"{blueprint}.{endpoint}" if blueprint else endpoint
            )
        if blueprint:
            endpoints.add(blueprint)
    return endpoints


def _run_templates(
    root: Path,
    endpoints: Iterable[str],
    errors: list[str],
) -> list[Finding]:
    try:
        return list(analyze_templates(root, known_endpoints=endpoints))
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"Template analyzer failed: {exc}")
        return []


def _run_security(
    root: Path, errors: list[str], run_bandit: bool
) -> list[Finding]:
    try:
        result = analyze_security(root, run_bandit=run_bandit)
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


def _run_dependencies(
    root: Path, errors: list[str]
) -> tuple[list[Finding], bool]:
    try:
        result = analyze_dependencies(root)
        errors.extend(result.get("errors", []))
        return list(result.get("findings", [])), bool(result.get("scanned"))
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"Dependency analyzer failed: {exc}")
        return [], False


def analyze_production(
    project_path: str | Path,
    scan_dependencies: bool | None = None,
    run_bandit: bool | None = None,
    config: Config | None = None,
) -> dict[str, Any]:
    """
    Run every analyzer and return an aggregated production assessment.

    ``scan_dependencies`` runs the CVE scan (pip-audit), which needs
    network access. ``run_bandit`` folds in a Bandit scan. Either may be
    None to inherit from ``config`` (default: on). ``config`` also drives
    rule ignore/select lists, severity overrides, the category floor, and
    the ``fail_on`` policy behind ``production_ready``.
    """

    root = Path(project_path).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Project path does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Project path is not a directory: {root}")

    config = config or Config()
    if scan_dependencies is None:
        scan_dependencies = config.scan_dependencies
    if run_bandit is None:
        run_bandit = config.run_bandit
    floor = config.category_floor

    errors: list[str] = []
    endpoints = _known_endpoints(root, errors)

    # Each collector gets its own error list so the categories can run on
    # threads (the two slow ones - dependencies and Bandit - are almost
    # entirely subprocess/network wait).
    jobs: dict[str, Any] = {
        "flask": lambda e: _run_flask(root, e),
        "architecture": lambda e: _run_architecture(root, e),
        "templates": lambda e: _run_templates(root, endpoints, e),
        "deployment": lambda e: _run_deployment(root, e),
        "security": lambda e: _run_security(root, e, run_bandit),
        "database": lambda e: _run_database(root, e),
        "code_quality": lambda e: _run_code_quality(root, e),
    }
    if scan_dependencies:
        jobs["dependencies"] = lambda e: _run_dependencies(root, e)

    job_errors: dict[str, list[str]] = {name: [] for name in jobs}
    raw: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {
            pool.submit(func, job_errors[name]): name
            for name, func in jobs.items()
        }
        for future, name in futures.items():
            raw[name] = future.result()
    for name in jobs:
        errors.extend(job_errors[name])

    if scan_dependencies:
        dependency_findings, dependencies_scanned = raw["dependencies"]
    else:
        dependency_findings, dependencies_scanned = [], False

    category_findings: dict[str, list[Finding]] = {
        "flask": raw["flask"],
        "architecture": raw["architecture"],
        "templates": raw["templates"],
        "deployment": raw["deployment"],
        "security": raw["security"],
        "database": raw["database"],
        "dependencies": dependency_findings,
        "code_quality": raw["code_quality"],
    }

    # Apply ignore / select / severity-override policy.
    category_findings = {
        name: config.apply(findings)
        for name, findings in category_findings.items()
    }

    all_findings = [
        finding
        for findings in category_findings.values()
        for finding in findings
    ]

    categories: dict[str, dict[str, Any]] = {}
    low_categories: list[tuple[str, int]] = []
    for name, findings in category_findings.items():
        score = weighted_score(findings)
        cat_blockers, _, _ = classify_findings(findings)
        categories[name] = {
            "score": score,
            "summary": build_summary(findings).model_dump(),
            "finding_count": len(findings),
            "blocker_count": len(cat_blockers),
        }
        if name == "dependencies":
            categories[name]["scanned"] = dependencies_scanned
        if score < floor:
            low_categories.append((name, score))

    blockers, advisories, notes = classify_findings(all_findings)
    blockers = _sort_findings(blockers)
    advisories = _sort_findings(advisories)
    notes = _sort_findings(notes)

    blocking_reasons: list[str] = []
    if blockers:
        counts: dict[str, int] = {}
        for finding in blockers:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        for category, count in sorted(counts.items()):
            blocking_reasons.append(f"{count} blocker(s) in {category}")
    for name, score in low_categories:
        blocking_reasons.append(
            f"{name} category score {score} is below the floor of {floor}"
        )

    if config.fail_on == "advisories" and advisories:
        blocking_reasons.append(f"{len(advisories)} advisory finding(s)")
    elif config.fail_on == "any" and (advisories or notes):
        blocking_reasons.append(
            f"{len(advisories) + len(notes)} non-blocker finding(s)"
        )
    elif config.fail_on == "never":
        blocking_reasons = []

    return {
        "success": True,
        "project_path": str(root),
        "overall_score": weighted_score(all_findings),
        "production_ready": not blocking_reasons,
        "blocking_reasons": blocking_reasons,
        "fail_on": config.fail_on,
        "summary": build_summary(all_findings).model_dump(),
        "categories": categories,
        "blockers": [f.model_dump(mode="json") for f in blockers],
        "advisories": [f.model_dump(mode="json") for f in advisories],
        "notes": [f.model_dump(mode="json") for f in notes],
        "errors": errors,
    }
