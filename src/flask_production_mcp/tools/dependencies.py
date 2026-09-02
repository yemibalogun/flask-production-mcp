"""MCP tool for scanning a Flask project's dependencies for CVEs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.base import build_audit_result
from flask_production_mcp.analyzers.dependencies import analyze_dependencies


def audit_dependencies(
    project_path: str = ".",
) -> dict[str, Any]:
    """
    Scan a Flask project's ``requirements*.txt`` files for dependencies
    with known vulnerabilities (via pip-audit / the PyPI and OSV advisory
    databases).

    The response adds ``manifests`` (files scanned) and ``scanned`` (False
    when no scan could run - no requirements file, pip-audit missing, or
    the advisory database was unreachable) so a clean result is never
    confused with an unchecked one.

    Requires network access. The project is never imported or executed.
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

        result = analyze_dependencies(project)

        payload = build_audit_result(
            project,
            result.get("findings", []),
            errors=result.get("errors", []),
        ).model_dump(mode="json")
        payload["manifests"] = result.get("manifests", [])
        payload["scanned"] = bool(result.get("scanned"))

        return payload

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
            "error": f"Dependency audit failed: {exc}",
        }
