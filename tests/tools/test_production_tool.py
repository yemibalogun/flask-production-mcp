"""End-to-end tests for the unified production audit."""

from __future__ import annotations

import json
from pathlib import Path

from flask_production_mcp.tools.production import audit_flask_production


def test_production_audit_shape(flawed_flask_project: Path) -> None:
    result = audit_flask_production(str(flawed_flask_project))

    assert result["success"] is True
    for key in (
        "overall_score",
        "production_ready",
        "blocking_reasons",
        "summary",
        "categories",
        "blockers",
        "warnings",
        "recommendations",
        "errors",
    ):
        assert key in result

    json.dumps(result)


def test_production_audit_runs_every_analyzer(
    flawed_flask_project: Path,
) -> None:
    result = audit_flask_production(str(flawed_flask_project))

    categories = result["categories"]
    assert set(categories) == {
        "flask",
        "security",
        "database",
        "code_quality",
    }

    # Every analyzer found at least the issue planted for it.
    assert categories["flask"]["finding_count"] >= 2
    assert categories["security"]["finding_count"] >= 1
    assert categories["database"]["finding_count"] >= 1
    assert categories["code_quality"]["finding_count"] >= 1


def test_production_audit_flags_not_ready(
    flawed_flask_project: Path,
) -> None:
    result = audit_flask_production(str(flawed_flask_project))

    assert result["production_ready"] is False
    assert result["blocking_reasons"]
    assert result["overall_score"] < 100

    blocker_categories = {b["category"] for b in result["blockers"]}
    assert blocker_categories  # at least one critical/high finding


def test_production_audit_clean_project_is_ready(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n\n"
        "app = Flask(__name__)\n\n"
        "SECRET_KEY = __import__('os').environ['SECRET_KEY']\n\n"
        "from flask_limiter import Limiter\n"
        "from flask_limiter.util import get_remote_address\n"
        "limiter = Limiter(get_remote_address, app=app, "
        "default_limits=['100/hour'])\n\n"
        "@app.get('/health')\n"
        "def health():\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )

    result = audit_flask_production(str(tmp_path))

    assert result["success"] is True
    assert result["categories"]["flask"]["score"] == 100
    assert result["categories"]["code_quality"]["score"] == 100


def test_production_audit_missing_path() -> None:
    result = audit_flask_production("/does/not/exist/x")

    assert result["success"] is False
    assert "error" in result
