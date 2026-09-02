"""MCP tool for auditing a Flask project's Jinja/HTML templates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.base import build_audit_result
from flask_production_mcp.analyzers.flask import discover_flask_project
from flask_production_mcp.analyzers.templates import analyze_templates


def _known_endpoints(project: Path) -> set[str]:
    try:
        architecture = discover_flask_project(str(project)).get(
            "flask_architecture", {}
        )
    except Exception:
        return set()

    endpoints: set[str] = {"static"}
    for route in architecture.get("routes", []):
        endpoint = route.get("endpoint")
        blueprint = route.get("blueprint")
        if endpoint:
            endpoints.add(
                f"{blueprint}.{endpoint}" if blueprint else endpoint
            )
        if blueprint:
            endpoints.add(blueprint)
    return endpoints


def audit_templates(
    project_path: str = ".",
) -> dict[str, Any]:
    """
    Audit a Flask project's Jinja/HTML templates.

    Detects state-changing forms with no CSRF field, autoescaping bypassed
    with ``| safe`` or ``{% autoescape false %}``, and ``url_for()`` calls
    that point at endpoints which do not exist.

    Templates are inspected as text; the project is never rendered.
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

        findings = analyze_templates(
            project,
            known_endpoints=_known_endpoints(project),
        )

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
            "error": f"Template audit failed: {exc}",
        }
