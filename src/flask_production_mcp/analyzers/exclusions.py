"""Rules for excluding files from application security analysis."""

from __future__ import annotations

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