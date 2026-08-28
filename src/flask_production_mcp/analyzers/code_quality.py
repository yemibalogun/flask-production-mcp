"""Static code-quality analyzer for Flask Production MCP."""

from __future__ import annotations

import ast
from pathlib import Path

from flask_production_mcp.models.findings import (
    Confidence,
    Finding,
    Severity,
)


def analyze_code_quality_file(
    file_path: Path,
) -> list[Finding]:
    """
    Analyze one Python file for production-relevant code-quality issues.

    The analyzer intentionally uses AST for Python syntax and calls,
    while comments such as TODO/FIXME are detected from source text.
    """

    try:
        source = file_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        # An unreadable file should not crash the complete audit.
        return [
            Finding(
                id="CQ-IO-001",
                category="code_quality",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="Unable to read Python source file",
                description=(
                    f"The analyzer could not read {file_path.name}: {exc}"
                ),
                recommendation=(
                    "Verify that the file exists and that the audit "
                    "process has permission to read it."
                ),
                file=str(file_path),
                line=None,
                metadata={
                    "error": str(exc),
                },
            )
        ]

    try:
        tree = ast.parse(
            source,
            filename=str(file_path),
        )
    except SyntaxError as exc:
        return [
            Finding(
                id="CQ-SYNTAX-001",
                category="code_quality",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Python syntax error detected",
                description=(
                    f"{file_path.name} contains invalid Python syntax: "
                    f"{exc.msg}."
                ),
                recommendation=(
                    "Fix the syntax error before deploying the application."
                ),
                file=str(file_path),
                line=exc.lineno,
                metadata={
                    "syntax_error": exc.msg,
                    "offset": exc.offset,
                },
            )
        ]

    findings: list[Finding] = []

    # AST checks provide reliable detection without depending on formatting.
    findings.extend(
        _find_bare_except(
            file_path,
            tree,
        )
    )

    findings.extend(
        _find_broad_exception(
            file_path,
            tree,
        )
    )

    findings.extend(
        _find_print_calls(
            file_path,
            tree,
        )
    )

    findings.extend(
        _find_breakpoint_calls(
            file_path,
            tree,
        )
    )

    findings.extend(
        _find_assert_statements(
            file_path,
            tree,
        )
    )

    # TODO/FIXME are comments and therefore aren't represented by Python's
    # normal AST. Scan source lines separately for these production leftovers.
    findings.extend(
        _find_todo_markers(
            file_path,
            source,
        )
    )

    return findings


def _find_bare_except(
    file_path: Path,
    tree: ast.AST,
) -> list[Finding]:
    """Detect ``except:`` clauses that catch every exception."""

    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue

        if node.type is not None:
            continue

        findings.append(
            Finding(
                id="CQ-CODE-001",
                category="code_quality",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="Bare except clause detected",
                description=(
                    "A bare except clause catches every exception, including "
                    "system-exiting exceptions, which can hide serious failures."
                ),
                recommendation=(
                    "Catch the specific exception types the code can handle "
                    "instead of using a bare except clause."
                ),
                file=str(file_path),
                line=node.lineno,
                metadata={
                    "pattern": "bare_except",
                },
            )
        )

    return findings


def _find_broad_exception(
    file_path: Path,
    tree: ast.AST,
) -> list[Finding]:
    """Detect ``except Exception`` handlers."""

    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue

        exception_type = node.type

        if not (
            isinstance(exception_type, ast.Name)
            and exception_type.id == "Exception"
        ):
            continue

        findings.append(
            Finding(
                id="CQ-CODE-002",
                category="code_quality",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                title="Broad Exception handler detected",
                description=(
                    "The code catches the base Exception class, which can "
                    "hide unexpected application failures."
                ),
                recommendation=(
                    "Catch only the exception types that can be handled "
                    "meaningfully and log unexpected failures appropriately."
                ),
                file=str(file_path),
                line=node.lineno,
                metadata={
                    "pattern": "except_exception",
                },
            )
        )

    return findings


def _find_print_calls(
    file_path: Path,
    tree: ast.AST,
) -> list[Finding]:
    """Detect calls to the built-in print() function."""

    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not (
            isinstance(node.func, ast.Name)
            and node.func.id == "print"
        ):
            continue

        findings.append(
            Finding(
                id="CQ-CODE-003",
                category="code_quality",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                title="print() statement detected",
                description=(
                    "The file contains a direct print() call. Console output "
                    "is generally inappropriate for production application "
                    "logging."
                ),
                recommendation=(
                    "Replace print() with the application's structured "
                    "logging system."
                ),
                file=str(file_path),
                line=node.lineno,
                metadata={
                    "pattern": "print_call",
                },
            )
        )

    return findings


def _find_breakpoint_calls(
    file_path: Path,
    tree: ast.AST,
) -> list[Finding]:
    """Detect breakpoint() calls that may have been left during debugging."""

    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not (
            isinstance(node.func, ast.Name)
            and node.func.id == "breakpoint"
        ):
            continue

        findings.append(
            Finding(
                id="CQ-CODE-004",
                category="code_quality",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="breakpoint() call detected",
                description=(
                    "A breakpoint() call remains in the source code and may "
                    "interrupt application execution when reached."
                ),
                recommendation=(
                    "Remove debugging breakpoints before deploying to production."
                ),
                file=str(file_path),
                line=node.lineno,
                metadata={
                    "pattern": "breakpoint_call",
                },
            )
        )

    return findings


def _find_assert_statements(
    file_path: Path,
    tree: ast.AST,
) -> list[Finding]:
    """
    Detect assert statements.

    Python can remove assert statements when optimization is enabled, so
    they should not be used for security, authorization, validation, or
    other production-critical guarantees.
    """

    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assert):
            continue

        findings.append(
            Finding(
                id="CQ-CODE-005",
                category="code_quality",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="assert statement detected",
                description=(
                    "An assert statement is used in application code. "
                    "Assertions may be disabled with Python optimization "
                    "and therefore should not enforce production-critical "
                    "validation or security rules."
                ),
                recommendation=(
                    "Replace production-critical assertions with explicit "
                    "validation and appropriate exception handling."
                ),
                file=str(file_path),
                line=node.lineno,
                metadata={
                    "pattern": "assert_statement",
                },
            )
        )

    return findings


def _find_todo_markers(
    file_path: Path,
    source: str,
) -> list[Finding]:
    """Detect TODO and FIXME markers left in source code."""

    findings: list[Finding] = []

    for line_number, line in enumerate(
        source.splitlines(),
        start=1,
    ):
        stripped = line.strip()

        # Only inspect comments so words such as TODO inside a normal
        # string literal do not become false positives.
        if not stripped.startswith("#"):
            continue

        upper_line = stripped.upper()

        marker: str | None = None

        if "TODO" in upper_line:
            marker = "TODO"
        elif "FIXME" in upper_line:
            marker = "FIXME"

        if marker is None:
            continue

        findings.append(
            Finding(
                id="CQ-CODE-006",
                category="code_quality",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                title=f"{marker} marker detected",
                description=(
                    f"A {marker} marker remains in the source code and may "
                    "represent unfinished or temporary implementation work."
                ),
                recommendation=(
                    f"Resolve the {marker} item or convert it into a tracked "
                    "issue before production deployment."
                ),
                file=str(file_path),
                line=line_number,
                metadata={
                    "pattern": marker.lower(),
                    "source_line": line.strip(),
                },
            )
        )

    return findings
