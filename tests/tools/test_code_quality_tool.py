"""Tests for the audit_code_quality MCP tool."""

from __future__ import annotations

from pathlib import Path

from flask_production_mcp.tools.code_quality import audit_code_quality


def test_audit_code_quality_standard_shape(
    flawed_flask_project: Path,
) -> None:
    result = audit_code_quality(str(flawed_flask_project))

    assert result["success"] is True
    for key in (
        "score",
        "summary",
        "findings",
        "recommendations",
        "errors",
        "files_analyzed",
    ):
        assert key in result


def test_audit_code_quality_detects_app_code_issues(
    flawed_flask_project: Path,
) -> None:
    result = audit_code_quality(str(flawed_flask_project))

    ids = {finding["id"] for finding in result["findings"]}

    # print(), bare except and assert all live in app/utils.py
    assert "CQ-CODE-001" in ids  # bare except
    assert "CQ-CODE-003" in ids  # print()
    assert "CQ-CODE-005" in ids  # assert


def test_audit_code_quality_ignores_test_files(
    flawed_flask_project: Path,
) -> None:
    result = audit_code_quality(str(flawed_flask_project))

    asserting_files = {
        finding["file"]
        for finding in result["findings"]
        if finding["id"] == "CQ-CODE-005"
    }

    assert not any("test" in Path(path).name for path in asserting_files)


def test_audit_code_quality_skips_virtualenv(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    venv = tmp_path / "venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "planted.py").write_text(
        "print('noise')\n",
        encoding="utf-8",
    )

    result = audit_code_quality(str(tmp_path))

    assert result["files_analyzed"] == 1
    assert result["findings"] == []
