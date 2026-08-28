"""MCP tools for Flask project inspection."""

from __future__ import annotations

from typing import Any

from flask_production_mcp.analyzers.flask import discover_flask_project


def inspect_flask_project(project_path: str) -> dict[str, Any]:
    """
    Inspect a Flask application's structure and technology stack.

    Args:
        project_path: Absolute or relative path to the Flask project.

    Returns:
        Structured information about the discovered project.
    """

    try:
        return {
            "success": True,
            **discover_flask_project(project_path),
        }

    except (FileNotFoundError, NotADirectoryError) as exc:
        return {
            "success": False,
            "error": str(exc),
        }

    except Exception as exc:
        # Prevent unexpected analyzer errors from terminating the MCP server.
        # The actual exception is returned as a controlled tool failure.
        return {
            "success": False,
            "error": f"Project inspection failed: {exc}",
        }