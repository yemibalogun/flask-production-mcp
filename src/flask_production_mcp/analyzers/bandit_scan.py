"""Bandit integration for the security layer.

Rather than reimplement a shallow subset of Bandit's checks, the security
analyzer runs Bandit and folds its results in, de-duplicated against the
project's own Flask-aware rules. A scan that cannot run is reported as an
error, never a silent pass.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from flask_production_mcp.models.findings import (
    Confidence,
    Finding,
    Severity,
)

_TIMEOUT = 120

_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
}

_CONFIDENCE_MAP = {
    "LOW": Confidence.LOW,
    "MEDIUM": Confidence.MEDIUM,
    "HIGH": Confidence.HIGH,
}

# Bandit excludes are prefix matches against the scan root.
_EXCLUDE = ",".join(
    [
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        "build",
        "dist",
        "migrations",
        "tests",
        "test",
    ]
)


def run_bandit(
    project_root: Path,
    timeout: int = _TIMEOUT,
) -> tuple[list[dict], str | None]:
    """Return (bandit result dicts, error message)."""

    command = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(project_root),
        "-f",
        "json",
        "-q",
        "-x",
        _EXCLUDE,
    ]

    try:
        completed = subprocess.run(
            command,
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return [], "bandit is not installed"
    except subprocess.TimeoutExpired:
        return [], f"bandit timed out after {timeout}s"

    stdout = (completed.stdout or "").strip()
    if not stdout:
        stderr = (completed.stderr or "").strip().splitlines()
        tail = stderr[-1] if stderr else f"exit code {completed.returncode}"
        return [], f"bandit produced no output: {tail}"

    try:
        report = json.loads(stdout)
    except json.JSONDecodeError:
        return [], "bandit output was not valid JSON"

    results = report.get("results", [])
    return [r for r in results if isinstance(r, dict)], None


def bandit_findings(
    project_root: Path,
    existing: list[Finding],
    timeout: int = _TIMEOUT,
) -> tuple[list[Finding], list[str]]:
    """
    Run Bandit and return findings not already covered by ``existing``.

    De-duplication is by (resolved file, line +/- 1) so the project's own
    Flask-aware wording wins for issues both tools catch.
    """

    root = Path(project_root).resolve()
    results, error = run_bandit(root, timeout)
    if error is not None:
        return [], [f"Bandit scan skipped: {error}"]

    covered: set[tuple[str, int]] = set()
    for finding in existing:
        if not finding.file or finding.line is None:
            continue
        try:
            key_file = str(Path(finding.file).resolve())
        except OSError:
            key_file = finding.file
        for delta in (-1, 0, 1):
            covered.add((key_file, finding.line + delta))

    findings: list[Finding] = []
    for result in results:
        filename = result.get("filename", "")
        line = result.get("line_number")
        try:
            resolved = str((root / filename).resolve()) if filename else ""
        except OSError:
            resolved = filename

        if line is not None and (resolved, line) in covered:
            continue

        test_id = result.get("test_id", "B000")
        text = (result.get("issue_text") or "").strip()
        severity = _SEVERITY_MAP.get(
            str(result.get("issue_severity", "")).upper(), Severity.LOW
        )
        confidence = _CONFIDENCE_MAP.get(
            str(result.get("issue_confidence", "")).upper(), Confidence.LOW
        )

        findings.append(
            Finding(
                id=f"SEC-BANDIT-{test_id}",
                category="security",
                severity=severity,
                confidence=confidence,
                title=(text.split(".")[0] or result.get("test_name", test_id))[
                    :120
                ],
                description=(
                    text
                    + (
                        f" (Bandit {test_id})"
                        if test_id not in text
                        else ""
                    )
                ),
                recommendation=(
                    "Review this Bandit finding. Details: "
                    + (result.get("more_info") or "https://bandit.readthedocs.io")
                ),
                file=resolved or None,
                line=line,
                metadata={
                    "source": "bandit",
                    "test_id": test_id,
                    "test_name": result.get("test_name"),
                    "cwe": (result.get("issue_cwe") or {}).get("id"),
                    "bandit_severity": result.get("issue_severity"),
                    "bandit_confidence": result.get("issue_confidence"),
                    "more_info": result.get("more_info"),
                },
            )
        )

    return findings, []
