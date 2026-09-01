"""MCP tool for running a Flask code-quality audit."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.base import build_audit_result
from flask_production_mcp.analyzers.code_quality import (
    analyze_code_quality_file,
)
from flask_production_mcp.analyzers.exclusions import iter_python_files


def audit_code_quality(
    project_path: str = ".",
) -> dict[str, Any]:
    """
    Analyze a Flask project's Python files for code-quality issues.

    The project is inspected statically and is never imported or executed.
    Virtual environments, caches and build directories are skipped.

    The response follows the standard audit shape (``success``, ``score``,
    ``summary``, ``findings``, ``recommendations``, ``errors``) plus
    ``files_analyzed``.
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

        files = list(iter_python_files(project, include_tests=False))

        findings = []
        for file_path in files:
            findings.extend(analyze_code_quality_file(file_path))

        payload = build_audit_result(project, findings).model_dump(
            mode="json"
        )
        payload["files_analyzed"] = len(files)

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
            "error": f"Code-quality audit failed: {exc}",
        }
