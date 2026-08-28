
"""MCP tool for running a Flask production security audit."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask_production_mcp.tools.security_audit import (
    run_security_audit,
)


def audit_security(
    project_path: str = ".",
) -> dict[str, Any]:
    """
    Audit a Flask project for common production security issues.

    This is the MCP boundary. Validation and analysis are delegated to
    the security-audit service.
    """

    try:
        # Resolve the path here so MCP clients receive a deterministic
        # absolute path in the response regardless of their working
        # directory.
        project = Path(project_path).expanduser().resolve()

        return run_security_audit(project)

    except FileNotFoundError as exc:
        return {
            "success": False,
            "error": str(exc),
        }

    except NotADirectoryError as exc:
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
        # MCP tools should return structured failures instead of allowing
        # an unexpected analyzer exception to terminate the server.
        return {
            "success": False,
            "error": f"Security audit failed: {exc}",
        }
