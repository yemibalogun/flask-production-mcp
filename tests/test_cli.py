"""Tests for the command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from flask_production_mcp.cli import main


@pytest.fixture
def clean_project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n\n"
        "app = Flask(__name__)\n\n"
        "SECRET_KEY = __import__('os').environ['SECRET_KEY']\n\n"
        "from flask_limiter import Limiter\n"
        "from flask_limiter.util import get_remote_address\n"
        "limiter = Limiter(get_remote_address, app=app)\n\n"
        "@app.get('/health')\n"
        "@limiter.limit('5/minute')\n"
        "def health():\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def csrf_bug_project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "from flask_limiter import Limiter\n"
        "from flask_limiter.util import get_remote_address\n"
        "limiter = Limiter(get_remote_address, app=app)\n"
        "@app.post('/x')\n"
        "@limiter.limit('5/minute')\n"
        "def x():\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )
    tpl = tmp_path / "templates"
    tpl.mkdir()
    (tpl / "p.html").write_text(
        '<form method="post" action="/x"><button>Go</button></form>',
        encoding="utf-8",
    )
    return tmp_path


def test_audit_clean_project_exits_zero(clean_project, capsys) -> None:
    code = main(
        ["audit", str(clean_project), "--skip-deps", "--skip-bandit"]
    )
    out = capsys.readouterr().out

    assert code == 0
    assert "production ready" in out.lower()


def test_audit_blocker_exits_one(csrf_bug_project, capsys) -> None:
    code = main(
        ["audit", str(csrf_bug_project), "--skip-deps", "--skip-bandit"]
    )
    out = capsys.readouterr().out

    assert code == 1
    assert "BLOCKERS" in out
    assert "TMPL-CSRF-001" in out


def test_audit_json_output(clean_project, capsys) -> None:
    code = main(
        [
            "audit",
            str(clean_project),
            "--skip-deps",
            "--skip-bandit",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["success"] is True
    assert "categories" in payload


def test_audit_github_annotations(csrf_bug_project, capsys) -> None:
    main(
        [
            "audit",
            str(csrf_bug_project),
            "--skip-deps",
            "--skip-bandit",
            "--github",
        ]
    )
    out = capsys.readouterr().out

    assert out.startswith("::error ")
    assert "TMPL-CSRF-001" in out


def test_fail_on_never_always_exits_zero(csrf_bug_project) -> None:
    code = main(
        [
            "audit",
            str(csrf_bug_project),
            "--skip-deps",
            "--skip-bandit",
            "--fail-on",
            "never",
        ]
    )

    assert code == 0


def test_config_file_ignore_rule(csrf_bug_project, capsys) -> None:
    (csrf_bug_project / "flask-production.toml").write_text(
        'ignore = ["TMPL-CSRF-001"]\n', encoding="utf-8"
    )

    code = main(
        ["audit", str(csrf_bug_project), "--skip-deps", "--skip-bandit"]
    )

    assert code == 0
    assert "TMPL-CSRF-001" not in capsys.readouterr().out


def test_audit_bad_path_exits_two(capsys) -> None:
    code = main(["audit", "/no/such/path/here"])

    assert code == 2
