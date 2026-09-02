"""MCP tool for auditing deployment configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.base import build_audit_result
from flask_production_mcp.analyzers.deployment import analyze_deployment


def audit_deployment(
    project_path: str = ".",
) -> dict[str, Any]:
    """
    Check a Flask project's deployment configuration.

    Scans the Dockerfile, docker-compose, the Gunicorn config, a Procfile
    and entrypoint scripts for: containers running as root, the Flask
    development server used as the container command, debug mode enabled
    via the environment, secrets baked into an image or compose file,
    database ports published to the host, and Gunicorn auto-reload.

    Files are inspected as text; nothing is executed.
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

        findings = analyze_deployment(project)

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
            "error": f"Deployment audit failed: {exc}",
        }
