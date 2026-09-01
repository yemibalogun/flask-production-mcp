"""MCP tool for running a Flask database audit."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.base import build_audit_result
from flask_production_mcp.analyzers.database import analyze_database


def _to_jsonable(value: Any) -> Any:
    """Recursively convert dataclass output into JSON-serializable data."""

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, dict):
        return {key: _to_jsonable(item) for key, item in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_to_jsonable(item) for item in value]

    return value


def audit_database(
    project_path: str = ".",
) -> dict[str, Any]:
    """
    Analyze a Flask project's database architecture and performance.

    The underlying analyzer performs static AST analysis only. The target
    Flask application is never imported or executed.

    The response follows the standard audit shape (``success``, ``score``,
    ``summary``, ``findings``, ``recommendations``, ``errors``) plus the
    database-specific keys ``models``, ``queries``, ``raw_sql``,
    ``sqlalchemy_detected`` and ``flask_sqlalchemy_detected``.
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

        result = analyze_database(project)

        parse_errors = result.get("parse_errors", [])

        audit = build_audit_result(
            project,
            result.get("findings", []),
            errors=[
                f"{error.get('file')}: {error.get('error')}"
                for error in parse_errors
            ],
        )

        payload = audit.model_dump(mode="json")

        payload["sqlalchemy_detected"] = bool(
            result.get("sqlalchemy_detected", False)
        )
        payload["flask_sqlalchemy_detected"] = bool(
            result.get("flask_sqlalchemy_detected", False)
        )
        payload["models"] = [
            _to_jsonable(asdict(model))
            for model in result.get("models", [])
        ]
        payload["queries"] = [
            _to_jsonable(asdict(query))
            for query in result.get("queries", [])
        ]
        payload["raw_sql"] = [
            _to_jsonable(asdict(usage))
            for usage in result.get("raw_sql", [])
        ]
        payload["parse_errors"] = parse_errors

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
            "error": f"Database audit failed: {exc}",
        }
