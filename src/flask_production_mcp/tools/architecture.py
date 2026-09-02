"""MCP tool for Flask-architecture checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.architecture import analyze_architecture
from flask_production_mcp.analyzers.base import build_audit_result


def audit_architecture(
    project_path: str = ".",
) -> dict[str, Any]:
    """
    Check a Flask project for architecture-level mistakes.

    Detects extensions bound to an app at import time, a module-level
    Flask() app competing with an app factory, hardcoded SECRET_KEY
    fallbacks, db.create_all() used instead of migrations, unguarded
    app.run(), and blueprints that are never registered.

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

        findings = analyze_architecture(project)

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
            "error": f"Architecture audit failed: {exc}",
        }
