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
