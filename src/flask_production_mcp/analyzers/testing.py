"""Test-suite health checks.

Static only - the test suite is never run. This reads what is already on
disk: whether a suite exists at all, an existing ``coverage.xml`` report
if the project's own CI produced one, and how the number of tests
compares to the number of routes.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from flask_production_mcp.analyzers.exclusions import (
    is_test_file,
    iter_python_files,
)
from flask_production_mcp.models.findings import (
    Confidence,
    Finding,
    Severity,
)

# Below this line rate an existing coverage report is flagged.
_COVERAGE_FLOOR = 0.60

_ROUTE_DECORATOR = re.compile(
    r"@\s*\w+\.(route|get|post|put|patch|delete)\b"
)
_TEST_FUNC = re.compile(r"^\s*(async\s+)?def\s+test_\w*", re.MULTILINE)


def _coverage_line_rate(root: Path) -> tuple[float, Path] | None:
    for name in ("coverage.xml", "cobertura.xml"):
        report = root / name
        if not report.is_file():
            continue
        try:
            tree = ET.parse(report)
        except (OSError, ET.ParseError):
            continue
        rate = tree.getroot().get("line-rate")
        if rate is None:
            continue
        try:
            return float(rate), report
        except ValueError:
            continue
    return None


def analyze_testing(project_path: str | Path) -> list[Finding]:
    """Assess the presence and rough adequacy of a project's tests."""

    root = Path(project_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Testing analysis root is invalid: {root}")

    findings: list[Finding] = []

    app_files: list[Path] = []
    test_files: list[Path] = []
    for path in iter_python_files(root, include_tests=True):
        (test_files if is_test_file(path) else app_files).append(path)

    # ------------------------------------------------------------------
    # TEST-001: no test suite at all
    # ------------------------------------------------------------------
    if not test_files:
        findings.append(
            Finding(
                id="TEST-001",
                category="testing",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                title="No test suite found",
                description=(
                    "No test modules (a tests/ package, test_*.py, or "
                    "*_test.py) were found. Shipping application changes "
                    "with no automated tests makes every deploy a manual "
                    "regression risk."
                ),
                recommendation=(
                    "Add a pytest suite covering at least authentication, "
                    "the checkout/payment path, and each blueprint's core "
                    "routes."
                ),
                file=None,
                line=None,
                metadata={"app_modules": len(app_files)},
            )
        )
        return findings

    # ------------------------------------------------------------------
    # TEST-002: an existing coverage report is low
    # ------------------------------------------------------------------
    coverage = _coverage_line_rate(root)
    if coverage is not None:
        rate, report = coverage
        if rate < _COVERAGE_FLOOR:
            findings.append(
                Finding(
                    id="TEST-002",
                    category="testing",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title=f"Test coverage is {rate:.0%}",
                    description=(
                        f"{report.name} reports {rate:.0%} line coverage, "
                        f"below the {_COVERAGE_FLOOR:.0%} threshold. Large "
                        "untested areas are where production regressions "
                        "hide."
                    ),
                    recommendation=(
                        "Raise coverage on the lowest-covered modules "
                        "first; prioritise request handlers and anything "
                        "touching money or auth."
                    ),
                    file=str(report),
                    line=None,
                    metadata={"line_rate": round(rate, 4)},
                )
            )

    # ------------------------------------------------------------------
    # TEST-003: the suite is thin relative to the number of routes
    # ------------------------------------------------------------------
    route_count = 0
    for path in app_files:
        try:
            route_count += len(
                _ROUTE_DECORATOR.findall(
                    path.read_text(encoding="utf-8-sig", errors="replace")
                )
            )
        except OSError:
            continue

    test_count = 0
    for path in test_files:
        try:
            test_count += len(
                _TEST_FUNC.findall(
                    path.read_text(encoding="utf-8-sig", errors="replace")
                )
            )
        except OSError:
            continue

    if route_count >= 4 and test_count < route_count / 2:
        findings.append(
            Finding(
                id="TEST-003",
                category="testing",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                title=(
                    f"Only {test_count} tests for ~{route_count} routes"
                ),
                description=(
                    f"The project defines about {route_count} routes but "
                    f"has roughly {test_count} test functions. This is a "
                    "rough heuristic, not a coverage measurement, but a "
                    "ratio this low usually means whole blueprints are "
                    "untested."
                ),
                recommendation=(
                    "Add at least a smoke test per route (status code, "
                    "auth required, happy path) and generate a real "
                    "coverage report in CI."
                ),
                file=None,
                line=None,
                metadata={
                    "route_count": route_count,
                    "test_function_count": test_count,
                },
            )
        )

    return findings
