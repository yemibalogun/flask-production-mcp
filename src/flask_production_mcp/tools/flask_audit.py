"""MCP tool for auditing Flask application architecture."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.flask import analyze_flask


def audit_flask(
    project_path: str = ".",
) -> dict[str, Any]:
    """
    Audit a Flask application's architecture for production-readiness issues.

    Unlike ``inspect_flask_project`` (which only describes the application),
    this returns structured findings and a score. It currently detects
    explicitly enabled debug mode and duplicate route declarations.

    The project is inspected statically and is never imported or executed.
    """

    try:
        project = Path(project_path).expanduser().resolve()

        return analyze_flask(project).model_dump(mode="json")

    except (FileNotFoundError, NotADirectoryError) as exc:
        return {
            "success": False,
            "error": str(exc),
        }

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
            "error": f"Flask audit failed: {exc}",
        }
