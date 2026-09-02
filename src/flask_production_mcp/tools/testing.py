"""MCP tool for assessing a Flask project's test suite."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.base import build_audit_result
from flask_production_mcp.analyzers.testing import analyze_testing


def audit_testing(
    project_path: str = ".",
) -> dict[str, Any]:
    """
    Assess whether a Flask project has an adequate test suite.

    Static only - the tests are never run. Reports: no suite at all, a low
    line-rate in an existing coverage.xml, and a test count that looks
    thin next to the number of routes.

    The project is inspected statically and is never imported or executed.
    """

    try:
        project = Path(project_path).expanduser().resolve()

        if not project.exists():
            return {
                "success": False,
                "error": f"Project path does not exist: {project}",
            }

        if not project.is_dir():
            return {
                "success": False,
                "error": f"Project path is not a directory: {project}",
            }

        findings = analyze_testing(project)

        return build_audit_result(project, findings).model_dump(mode="json")

    except PermissionError as exc:
        return {
            "success": False,
            "error": f"Permission denied: {exc}",
        }

    except OSError as exc:
        return {
            "success": False,
            "error": f"Unable to access project: {exc}",
        }

    except Exception as exc:
        return {
            "success": False,
            "error": f"Testing audit failed: {exc}",
        }
