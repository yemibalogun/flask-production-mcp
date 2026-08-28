"""Flask project discovery and architecture analysis."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any


# Directories that normally contain generated dependencies, caches, or
# version-control data. Traversing these would dramatically increase audit
# time and could produce thousands of irrelevant files.
IGNORED_DIRECTORIES: frozenset[str] = frozenset(
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
        "dist",
        "build",
    }
)


def discover_flask_project(project_path: str) -> dict[str, Any]:
    """
    Discover the structure and major Flask indicators of a project.

    The analyzer intentionally performs static inspection only. It does not
    import or execute the target application's code, which is important from
    both a security and reliability perspective.
    """

    root = Path(project_path).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Project path does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Project path is not a directory: {root}")

    python_files: list[Path] = []
    template_files: list[Path] = []
    static_files: list[Path] = []

    for path in root.rglob("*"):
        # Skip directories that contain dependencies or generated files.
        if any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue

        if not path.is_file():
            continue

        suffix = path.suffix.lower()

        if suffix == ".py":
            python_files.append(path)
        elif suffix in {".html", ".jinja", ".jinja2"}:
            template_files.append(path)
        elif suffix in {
            ".css",
            ".js",
            ".mjs",
            ".ts",
            ".tsx",
            ".png",
            ".jpg",
            ".jpeg",
            ".svg",
            ".webp",
        }:
            static_files.append(path)

    indicators = _detect_indicators(root, python_files)

    return {
        "project_path": str(root),
        "python_files": len(python_files),
        "template_files": len(template_files),
        "static_files": len(static_files),
        "directories": _discover_directories(root),
        "flask_indicators": indicators,
    }


def _discover_directories(root: Path) -> list[str]:
    """Return relevant project directories."""

    directories: list[str] = []

    for path in root.rglob("*"):
        if not path.is_dir():
            continue

        if any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue

        directories.append(str(path.relative_to(root)))

    return sorted(directories)


def _detect_indicators(
    root: Path,
    python_files: list[Path],
) -> dict[str, Any]:
    """Detect Flask-related technologies through static source inspection."""

    filenames = {path.name.lower() for path in python_files}

    indicators: dict[str, Any] = {
        "app.py": "app.py" in filenames,
        "wsgi.py": "wsgi.py" in filenames,
        "pyproject.toml": (root / "pyproject.toml").exists(),
        "requirements.txt": (root / "requirements.txt").exists(),
        ".env": (root / ".env").exists(),
        "flask": False,
        "sqlalchemy": False,
        "flask_sqlalchemy": False,
        "flask_migrate": False,
        "flask_login": False,
        "flask_wtf": False,
        "flask_limiter": False,
        "oauth": False,
    }

    for source_file in python_files:
        try:
            source = source_file.read_text(
                encoding="utf-8",
                errors="replace",
            )

            tree = ast.parse(source)

        except (OSError, SyntaxError):
            # A single malformed/unreadable source file should not prevent the
            # entire project from being analyzed.
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules = [node.module or ""]
            else:
                continue

            for module in modules:
                normalized = module.lower()

                if normalized == "flask" or normalized.startswith("flask."):
                    indicators["flask"] = True

                if "sqlalchemy" in normalized:
                    indicators["sqlalchemy"] = True

                if "flask_sqlalchemy" in normalized:
                    indicators["flask_sqlalchemy"] = True

                if "flask_migrate" in normalized:
                    indicators["flask_migrate"] = True

                if "flask_login" in normalized:
                    indicators["flask_login"] = True

                if "flask_wtf" in normalized:
                    indicators["flask_wtf"] = True

                if "flask_limiter" in normalized:
                    indicators["flask_limiter"] = True

                if any(
                    provider in normalized
                    for provider in (
                        "authlib",
                        "flask_dance",
                        "oauthlib",
                    )
                ):
                    indicators["oauth"] = True

    return indicators