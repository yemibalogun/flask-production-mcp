"""Tests for the test-suite health analyzer."""

from __future__ import annotations

from pathlib import Path

from flask_production_mcp.analyzers.testing import analyze_testing


def _write(project: Path, rel: str, content: str) -> None:
    path = project / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _ids(project: Path) -> list[str]:
    return sorted(f.id for f in analyze_testing(project))


def test_no_tests_at_all(tmp_path: Path) -> None:
    _write(tmp_path, "app/__init__.py", "x = 1\n")

    findings = analyze_testing(tmp_path)

    assert [f.id for f in findings] == ["TEST-001"]
    assert findings[0].severity.value == "high"


def test_a_test_module_clears_test_001(tmp_path: Path) -> None:
    _write(tmp_path, "app/__init__.py", "x = 1\n")
    _write(tmp_path, "tests/test_app.py", "def test_x():\n    assert True\n")

    assert "TEST-001" not in _ids(tmp_path)


def test_low_coverage_report_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "app/__init__.py", "x = 1\n")
    _write(tmp_path, "tests/test_app.py", "def test_x():\n    assert True\n")
    _write(
        tmp_path,
        "coverage.xml",
        '<?xml version="1.0"?>\n<coverage line-rate="0.31"></coverage>',
    )

    findings = analyze_testing(tmp_path)
    test_002 = [f for f in findings if f.id == "TEST-002"]
    assert test_002
    assert test_002[0].metadata["line_rate"] == 0.31


def test_good_coverage_report_is_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "app/__init__.py", "x = 1\n")
    _write(tmp_path, "tests/test_app.py", "def test_x():\n    assert True\n")
    _write(
        tmp_path,
        "coverage.xml",
        '<?xml version="1.0"?>\n<coverage line-rate="0.85"></coverage>',
    )

    assert "TEST-002" not in _ids(tmp_path)


def test_thin_suite_relative_to_routes(tmp_path: Path) -> None:
    routes = "\n\n".join(
        f'@app.route("/r{i}")\ndef r{i}():\n    return "ok"'
        for i in range(8)
    )
    _write(tmp_path, "app/routes.py", f"from app import app\n\n{routes}\n")
    _write(
        tmp_path,
        "tests/test_smoke.py",
        "def test_one():\n    assert True\n",
    )

    assert "TEST-003" in _ids(tmp_path)


def test_adequate_suite_is_not_flagged_as_thin(tmp_path: Path) -> None:
    routes = "\n\n".join(
        f'@app.route("/r{i}")\ndef r{i}():\n    return "ok"'
        for i in range(4)
    )
    tests = "\n\n".join(
        f"def test_r{i}():\n    assert True" for i in range(6)
    )
    _write(tmp_path, "app/routes.py", f"from app import app\n\n{routes}\n")
    _write(tmp_path, "tests/test_routes.py", tests + "\n")

    assert "TEST-003" not in _ids(tmp_path)
