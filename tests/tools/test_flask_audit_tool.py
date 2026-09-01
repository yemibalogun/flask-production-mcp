"""Tests for the audit_flask MCP tool."""

from __future__ import annotations

from pathlib import Path

from flask_production_mcp.tools.flask_audit import audit_flask

STANDARD_KEYS = {
    "success",
    "project_path",
    "score",
    "findings",
    "summary",
    "recommendations",
    "errors",
}


def test_audit_flask_returns_standard_shape(flawed_flask_project: Path) -> None:
    result = audit_flask(str(flawed_flask_project))

    assert result["success"] is True
    assert STANDARD_KEYS.issubset(result.keys())
    assert 0 <= result["score"] <= 100


def test_audit_flask_detects_debug_and_duplicate_route(
    flawed_flask_project: Path,
) -> None:
    result = audit_flask(str(flawed_flask_project))

    ids = {finding["id"] for finding in result["findings"]}

    assert "FLASK-CONFIG-001" in ids
    assert "FLASK-ROUTE-001" in ids
    assert result["score"] < 100


def test_audit_flask_missing_path_is_structured_error() -> None:
    result = audit_flask("/no/such/project/path")

    assert result["success"] is False
    assert "error" in result


def test_audit_flask_clean_project(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n\napp = Flask(__name__)\n",
        encoding="utf-8",
    )

    result = audit_flask(str(tmp_path))

    assert result["success"] is True
    assert result["score"] == 100
    assert result["findings"] == []
