
"""Security-audit service layer for Flask Production MCP."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.security import analyze_security
from flask_production_mcp.models.findings import AuditResult


def run_security_audit(
    project_path: str | Path,
) -> dict[str, Any]:
    """
    Run the security analyzer and return a JSON-serializable result.

    This service layer intentionally contains no MCP-specific logic.
    It can therefore be reused by tests, CLI commands, or future
    automation workflows.
    """

    project = Path(project_path).expanduser().resolve()

    if not project.exists():
        raise FileNotFoundError(
            f"Project path does not exist: {project}"
        )

    if not project.is_dir():
        raise NotADirectoryError(
            f"Project path is not a directory: {project}"
        )

    result: AuditResult = analyze_security(project)

    return result.model_dump(mode="json")


def security_audit_summary(
    project_path: str | Path,
) -> dict[str, Any]:
    """
    Produce a compact security posture summary.

    This avoids duplicating scoring and severity calculations because
    those are already performed by the analyzer.
    """

    result = run_security_audit(project_path)

    summary = result.get("summary", {})

    critical = int(summary.get("critical", 0))
    high = int(summary.get("high", 0))
    medium = int(summary.get("medium", 0))
    low = int(summary.get("low", 0))
    info = int(summary.get("info", 0))

    return {
        "project_path": result["project_path"],
        "score": int(result.get("score", 0)),
        "total_findings": len(result.get("findings", [])),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "production_ready": (
            critical == 0
            and high == 0
        ),
        "errors": result.get("errors", []),
    }
