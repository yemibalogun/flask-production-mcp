"""End-to-end tests for the unified production audit.

Dependency scanning is disabled in most tests (``scan_dependencies=False``)
so the suite never touches the network; one dedicated test stubs the
scanner to exercise that path.
"""

from __future__ import annotations

import json
from pathlib import Path

import flask_production_mcp.analyzers.production as production
from flask_production_mcp.tools.production import audit_flask_production


def _audit(path: Path, **kw):
    kw.setdefault("scan_dependencies", False)
    kw.setdefault("run_bandit", False)
    return audit_flask_production(str(path), **kw)


def test_production_audit_shape(flawed_flask_project: Path) -> None:
    result = _audit(flawed_flask_project)

    assert result["success"] is True
    for key in (
        "overall_score",
        "production_ready",
        "blocking_reasons",
        "summary",
        "categories",
        "blockers",
        "advisories",
        "notes",
        "errors",
    ):
        assert key in result

    json.dumps(result)


def test_production_audit_runs_every_analyzer(
    flawed_flask_project: Path,
) -> None:
    result = _audit(flawed_flask_project)

    categories = result["categories"]
    assert set(categories) == {
        "flask",
        "architecture",
        "templates",
        "deployment",
        "testing",
        "security",
        "database",
        "dependencies",
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
    result = _audit(flawed_flask_project)

    assert result["production_ready"] is False
    assert result["blocking_reasons"]
    assert result["overall_score"] < 100

    blocker_categories = {b["category"] for b in result["blockers"]}
    assert blocker_categories  # at least one high-confidence blocker


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

    result = _audit(tmp_path)

    assert result["success"] is True
    assert result["categories"]["flask"]["score"] == 100
    assert result["categories"]["code_quality"]["score"] == 100
    assert result["production_ready"] is True
    assert result["blocking_reasons"] == []
    assert result["blockers"] == []


def test_low_confidence_findings_do_not_block(tmp_path: Path) -> None:
    """
    A pile of medium/low-confidence findings lowers the weighted score but
    must not, on its own, flip production_ready to False.
    """

    body = "\n".join(
        f"    # TODO: clean up step {i}\n    print({i})" for i in range(6)
    )
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n\n"
        "app = Flask(__name__)\n\n"
        "from flask_limiter import Limiter\n"
        "from flask_limiter.util import get_remote_address\n"
        "limiter = Limiter(get_remote_address, app=app)\n\n"
        "@app.get('/health')\n"
        "@limiter.limit('5/minute')\n"
        "def health():\n"
        f"{body}\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_health.py").write_text(
        "def test_health():\n    assert True\n", encoding="utf-8"
    )

    result = _audit(tmp_path)

    assert result["summary"]["critical"] == 0
    assert result["summary"]["high"] == 0
    assert result["blockers"] == []
    assert result["notes"]  # the TODO/print findings land here
    assert result["production_ready"] is True


def test_missing_csrf_template_is_a_blocker(tmp_path: Path) -> None:
    """The template analyzer must surface a CSRF-less POST form as a blocker."""

    (tmp_path / "app.py").write_text(
        "from flask import Flask\n\n"
        "app = Flask(__name__)\n\n"
        "from flask_limiter import Limiter\n"
        "from flask_limiter.util import get_remote_address\n"
        "limiter = Limiter(get_remote_address, app=app)\n\n"
        "@app.post('/delete')\n"
        "@limiter.limit('5/minute')\n"
        "def delete():\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "page.html").write_text(
        '<form method="post" action="/delete">'
        "<button>Delete</button></form>\n",
        encoding="utf-8",
    )

    result = _audit(tmp_path)

    blocker_ids = {b["id"] for b in result["blockers"]}
    assert "TMPL-CSRF-001" in blocker_ids
    assert result["production_ready"] is False
    assert result["categories"]["templates"]["blocker_count"] >= 1


def test_dependency_scan_is_wired_in(tmp_path, monkeypatch) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8"
    )

    def fake_analyze_dependencies(project_path, timeout=120):
        from flask_production_mcp.models.findings import (
            Confidence,
            Finding,
            Severity,
        )

        return {
            "findings": [
                Finding(
                    id="DEP-VULN-001",
                    category="dependencies",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    title="requests 2.19.1: 3 known vulnerabilities",
                    description="stub",
                    recommendation="Upgrade requests.",
                    file=str(tmp_path / "requirements.txt"),
                    line=1,
                    metadata={"package": "requests"},
                )
            ],
            "errors": [],
            "manifests": ["requirements.txt"],
            "scanned": True,
        }

    monkeypatch.setattr(
        production, "analyze_dependencies", fake_analyze_dependencies
    )

    result = audit_flask_production(
        str(tmp_path), scan_dependencies=True, run_bandit=False
    )

    deps = result["categories"]["dependencies"]
    assert deps["scanned"] is True
    assert deps["finding_count"] == 1
    # HIGH severity + MEDIUM confidence -> advisory, not a hard blocker.
    assert any(a["id"] == "DEP-VULN-001" for a in result["advisories"])


def test_production_audit_missing_path() -> None:
    result = audit_flask_production("/does/not/exist/x", scan_dependencies=False)

    assert result["success"] is False
    assert "error" in result
