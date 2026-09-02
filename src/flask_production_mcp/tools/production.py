"""MCP tool for the unified Flask production-readiness audit."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.production import analyze_production
from flask_production_mcp.config import load_config


def audit_flask_production(
    project_path: str = ".",
    scan_dependencies: bool | None = None,
    run_bandit: bool | None = None,
) -> dict[str, Any]:
    """
    Run a complete production-readiness audit of a Flask application.

    This runs every analyzer (architecture, templates, security, database,
    dependencies, code quality) and returns a single report:

    - ``overall_score`` (confidence-weighted) and per-category ``score``
    - ``production_ready`` with ``blocking_reasons``
    - ``blockers`` (high-confidence critical/high - these gate a release),
      ``advisories`` (other critical/high/medium - need a judgement call),
      and ``notes`` (low/info cleanups)

    ``scan_dependencies`` / ``run_bandit`` default to the project's
    ``flask-production.toml`` (or ``[tool.flask-production]`` in
    pyproject.toml), which also controls rule ignore/select lists,
    severity overrides and the ``fail_on`` policy. Pass False for either
    to force it off for this run.

    The project is inspected statically and is never imported or executed.
    """

    try:
        project = Path(project_path).expanduser().resolve()
        config = load_config(project)

        return analyze_production(
            project,
            scan_dependencies=scan_dependencies,
            run_bandit=run_bandit,
            config=config,
        )

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
