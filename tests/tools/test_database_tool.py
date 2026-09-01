"""Tests for the audit_database MCP tool."""

from __future__ import annotations

import json
from pathlib import Path

from flask_production_mcp.tools.database import audit_database


def test_audit_database_returns_standard_shape(
    flawed_flask_project: Path,
) -> None:
    result = audit_database(str(flawed_flask_project))

    assert result["success"] is True
    for key in (
        "score",
        "summary",
        "findings",
        "recommendations",
        "errors",
        "models",
        "queries",
        "raw_sql",
        "sqlalchemy_detected",
    ):
        assert key in result


def test_audit_database_is_json_serializable(
    flawed_flask_project: Path,
) -> None:
    result = audit_database(str(flawed_flask_project))

    # Must not raise: dataclass Path fields have to be converted to strings.
    json.dumps(result)


def test_audit_database_detects_models_and_raw_sql(
    flawed_flask_project: Path,
) -> None:
    result = audit_database(str(flawed_flask_project))

    assert result["flask_sqlalchemy_detected"] is True
    assert any(model["name"] == "User" for model in result["models"])
    assert any(
        finding["id"] == "DB-SEC-001" for finding in result["findings"]
    )


def test_audit_database_skips_virtualenv(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask_sqlalchemy import SQLAlchemy\n"
        "db = SQLAlchemy()\n",
        encoding="utf-8",
    )

    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "planted.py").write_text(
        "import sqlalchemy\n"
        "conn.execute('SELECT * FROM secrets')\n",
        encoding="utf-8",
    )

    result = audit_database(str(tmp_path))

    files = {usage["file"] for usage in result["raw_sql"]}
    assert not any(".venv" in path for path in files)


def test_audit_database_missing_path() -> None:
    result = audit_database("/no/such/path/here")

    assert result["success"] is False
    assert "error" in result
