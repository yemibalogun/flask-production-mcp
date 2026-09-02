"""Rules for excluding files from application security analysis."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

# Directories that normally contain tooling rather than application code.
#
# The MCP should inspect the user's application, not its own implementation
# or generated Python environments.
DEFAULT_EXCLUDED_DIRECTORIES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        "node_modules",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "site-packages",
        "dist",
        "build",
    }
)


def should_exclude_path(
    path: Path,
    project_root: Path,
) -> bool:
    """
    Determine whether a path should be excluded from source analysis.

    Paths are resolved before comparison so Windows paths such as:

        C:\\project\\src\\...

    and relative paths are handled consistently.
    """

    try:
        resolved_path = path.resolve()
        resolved_root = project_root.resolve()
    except OSError:
        # If the filesystem cannot resolve the path, fail safely and allow
        # the caller to decide whether to report the underlying error.
        return False

    # Never analyze anything outside the requested project.
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError:
        return True

    # Ignore known tooling/build directories.
    return any(
        directory in DEFAULT_EXCLUDED_DIRECTORIES
        for directory in resolved_path.parts
    )


# Directory names that normally contain test code rather than the
# application that gets deployed to production.
_TEST_DIRECTORIES: frozenset[str] = frozenset(
    {"tests", "test", "testing"}
)


def is_test_file(path: Path) -> bool:
    """Return True when a path looks like test code rather than app code."""

    if any(part in _TEST_DIRECTORIES for part in path.parts):
        return True

    name = path.name

    return (
        name == "conftest.py"
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def iter_python_files(
    project_root: Path,
    include_tests: bool = True,
) -> Iterator[Path]:
    """
    Yield every analyzable Python source file within a project.

    Tooling, cache, build, and virtual-environment directories are skipped
    so analyzers never waste time on dependencies or report findings that
    do not belong to the user's application. When ``include_tests`` is
    False, test modules are skipped as well - useful for production-code
    quality checks where test-only patterns (such as ``assert``) are
    expected and not defects.
    """

    root = Path(project_root).expanduser().resolve()

    for path in root.rglob("*.py"):
        if not path.is_file():
            continue

        if should_exclude_path(path, root):
            continue

        if not include_tests and is_test_file(path):
            continue

        yield path


_TEMPLATE_SUFFIXES: frozenset[str] = frozenset(
    {".html", ".htm", ".jinja", ".jinja2", ".j2", ".xml", ".txt"}
)


def iter_template_files(project_root: Path) -> Iterator[Path]:
    """
    Yield candidate Jinja/HTML template files within a project.

    Only files under a directory named ``templates`` are considered so
    that arbitrary ``.txt``/``.xml`` files elsewhere are not scanned as
    templates. Tooling and dependency directories are excluded.
    """

    root = Path(project_root).expanduser().resolve()

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        if path.suffix.lower() not in _TEMPLATE_SUFFIXES:
            continue

        if should_exclude_path(path, root):
            continue

        if path.suffix.lower() in {".html", ".htm"} or "templates" in path.parts:
            yield path


def is_mcp_source_file(
    path: Path,
    package_root: Path,
) -> bool:
    """Return True when a file belongs to this MCP's own source tree."""

    try:
        path.resolve().relative_to(package_root.resolve())
    except ValueError:
        return False

    return True
