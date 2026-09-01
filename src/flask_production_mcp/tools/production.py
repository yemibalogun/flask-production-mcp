"""MCP tool for the unified Flask production-readiness audit."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.production import analyze_production


def audit_flask_production(
    project_path: str = ".",
) -> dict[str, Any]:
    """
    Run a complete production-readiness audit of a Flask application.

    This runs every analyzer (architecture, security, database, code
    quality) and returns a single report:

    - ``overall_score`` and per-category ``score``
    - ``production_ready`` with ``blocking_reasons``
    - ``blockers`` (critical/high), ``warnings`` (medium) and
      ``recommendations`` (low/info)

    The project is inspected statically and is never imported or executed.
    """

    try:
        project = Path(project_path).expanduser().resolve()

        return analyze_production(project)

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
            "error": f"Production audit failed: {exc}",
        }
