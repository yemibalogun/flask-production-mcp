"""Tests for the Flask Production MCP code-quality analyzer."""

from __future__ import annotations

from pathlib import Path

from flask_production_mcp.analyzers.code_quality import (
    analyze_code_quality_file,
)
from flask_production_mcp.models.findings import Severity


def write_python_file(
    tmp_path: Path,
    relative_path: str,
    source: str,
) -> Path:
    """Create a temporary Python source file for AST analysis."""

    file_path = tmp_path / relative_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(source, encoding="utf-8")

    return file_path


def finding_ids(findings: list) -> set[str]:
    """Return finding IDs for concise assertions."""

    return {finding.id for finding in findings}


def test_detects_bare_except(tmp_path: Path) -> None:
    """Bare except clauses should be reported."""

    file_path = write_python_file(
        tmp_path,
        "app/routes.py",
        """
def process():
    try:
        do_work()
    except:
        return None
""",
    )

    findings = analyze_code_quality_file(file_path)

    assert "CQ-CODE-001" in finding_ids(findings)


def test_detects_broad_exception(tmp_path: Path) -> None:
    """Broad Exception handlers should be reported."""

    file_path = write_python_file(
        tmp_path,
        "app/services.py",
        """
def process():
    try:
        do_work()
    except Exception:
        return None
""",
    )

    findings = analyze_code_quality_file(file_path)

    assert "CQ-CODE-002" in finding_ids(findings)


def test_detects_print_statement(tmp_path: Path) -> None:
    """print() calls should be reported."""

    file_path = write_python_file(
        tmp_path,
        "app/debug.py",
        """
def process(value):
    print(value)
    return value
""",
    )

    findings = analyze_code_quality_file(file_path)

    assert "CQ-CODE-003" in finding_ids(findings)


def test_detects_breakpoint(tmp_path: Path) -> None:
    """breakpoint() calls should be reported."""

    file_path = write_python_file(
        tmp_path,
        "app/debug.py",
        """
def process(value):
    breakpoint()
    return value
""",
    )

    findings = analyze_code_quality_file(file_path)

    assert "CQ-CODE-004" in finding_ids(findings)


def test_detects_assert(tmp_path: Path) -> None:
    """assert statements should be reported."""

    file_path = write_python_file(
        tmp_path,
        "app/security.py",
        """
def validate(user):
    assert user is not None
""",
    )

    findings = analyze_code_quality_file(file_path)

    assert "CQ-CODE-005" in finding_ids(findings)


def test_detects_todo_comment(tmp_path: Path) -> None:
    """TODO markers should be reported."""

    file_path = write_python_file(
        tmp_path,
        "app/routes.py",
        """
def login():
    # TODO: implement proper authentication
    return "ok"
""",
    )

    findings = analyze_code_quality_file(file_path)

    assert "CQ-CODE-006" in finding_ids(findings)


def test_detects_fixme_comment(tmp_path: Path) -> None:
    """FIXME markers should be reported."""

    file_path = write_python_file(
        tmp_path,
        "app/routes.py",
        """
def checkout():
    # FIXME: handle payment failure
    return "ok"
""",
    )

    findings = analyze_code_quality_file(file_path)

    assert "CQ-CODE-006" in finding_ids(findings)


def test_clean_file_has_no_findings(tmp_path: Path) -> None:
    """Normal production-style code should not produce findings."""

    file_path = write_python_file(
        tmp_path,
        "app/services.py",
        """
def add_numbers(first: int, second: int) -> int:
    return first + second
""",
    )

    findings = analyze_code_quality_file(file_path)

    assert findings == []


def test_syntax_error_is_handled_safely(tmp_path: Path) -> None:
    """Invalid Python should not crash the analyzer."""

    file_path = write_python_file(
        tmp_path,
        "app/broken.py",
        """
def broken(
    return "invalid"
""",
    )

    findings = analyze_code_quality_file(file_path)

    assert findings

    syntax_finding = next(
        finding
        for finding in findings
        if finding.id == "CQ-SYNTAX-001"
    )

    assert syntax_finding.severity == Severity.HIGH
    assert syntax_finding.file == str(file_path)


def test_findings_include_line_numbers(tmp_path: Path) -> None:
    """AST-based findings should identify their source line."""

    file_path = write_python_file(
        tmp_path,
        "app/debug.py",
        """
def process(value):
    print(value)
""",
    )

    findings = analyze_code_quality_file(file_path)

    finding = next(
        finding
        for finding in findings
        if finding.id == "CQ-CODE-003"
    )

    assert finding.line == 3
