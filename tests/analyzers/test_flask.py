"""Tests for Flask project discovery."""

from __future__ import annotations

from pathlib import Path

from flask_production_mcp.analyzers.flask import (
    discover_flask_project,
)


def write_file(
    tmp_path: Path,
    relative_path: str,
    content: str = "",
) -> Path:
    """Create a temporary project file."""

    file_path = tmp_path / relative_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")

    return file_path


def test_discovers_basic_project_structure(
    tmp_path: Path,
) -> None:
    """The discovery layer should identify common Flask project files."""

    write_file(
        tmp_path,
        "app.py",
        """
from flask import Flask

app = Flask(__name__)
""",
    )

    write_file(
        tmp_path,
        "templates/index.html",
        "<h1>Hello</h1>",
    )

    write_file(
        tmp_path,
        "static/app.css",
        "body { margin: 0; }",
    )

    result = discover_flask_project(str(tmp_path))

    assert result["project_path"] == str(tmp_path.resolve())
    assert result["python_files"] == 1
    assert result["template_files"] == 1
    assert result["static_files"] == 1

    assert result["flask_indicators"]["app.py"] is True
    assert result["flask_indicators"]["flask"] is True


def test_detects_flask_extensions(
    tmp_path: Path,
) -> None:
    """Common Flask extensions should be detected from imports."""

    write_file(
        tmp_path,
        "app/extensions.py",
        """
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf import FlaskForm
from flask_limiter import Limiter
from authlib.integrations.flask_client import OAuth
""",
    )

    result = discover_flask_project(str(tmp_path))
    indicators = result["flask_indicators"]

    assert indicators["flask"] is True
    assert indicators["sqlalchemy"] is True
    assert indicators["flask_sqlalchemy"] is True
    assert indicators["flask_migrate"] is True
    assert indicators["flask_login"] is True
    assert indicators["flask_wtf"] is True
    assert indicators["flask_limiter"] is True
    assert indicators["oauth"] is True


def test_detects_project_configuration_files(
    tmp_path: Path,
) -> None:
    """Important deployment/configuration files should be detected."""

    write_file(tmp_path, "app.py", "from flask import Flask")
    write_file(tmp_path, "wsgi.py", "application = None")
    write_file(tmp_path, "pyproject.toml", "[project]")
    write_file(tmp_path, "requirements.txt", "Flask")
    write_file(tmp_path, ".env", "SECRET_KEY=example")

    result = discover_flask_project(str(tmp_path))
    indicators = result["flask_indicators"]

    assert indicators["app.py"] is True
    assert indicators["wsgi.py"] is True
    assert indicators["pyproject.toml"] is True
    assert indicators["requirements.txt"] is True
    assert indicators[".env"] is True


def test_ignores_dependency_and_cache_directories(
    tmp_path: Path,
) -> None:
    """Generated/dependency directories should not affect project counts."""

    write_file(
        tmp_path,
        "app.py",
        "from flask import Flask",
    )

    write_file(
        tmp_path,
        ".venv/lib/site-packages/fake.py",
        "print('ignored')",
    )

    write_file(
        tmp_path,
        "node_modules/package/index.js",
        "console.log('ignored')",
    )

    write_file(
        tmp_path,
        "__pycache__/cached.py",
        "print('ignored')",
    )

    write_file(
        tmp_path,
        ".git/config.py",
        "print('ignored')",
    )

    result = discover_flask_project(str(tmp_path))

    assert result["python_files"] == 1


def test_handles_malformed_python_safely(
    tmp_path: Path,
) -> None:
    """
    A malformed Python file should not prevent discovery of the rest
    of the project.
    """

    write_file(
        tmp_path,
        "app.py",
        """
from flask import Flask

app = Flask(__name__)
""",
    )

    write_file(
        tmp_path,
        "broken.py",
        """
def broken(
    this is invalid Python
""",
    )

    result = discover_flask_project(str(tmp_path))

    # The malformed file is still a Python file, but its AST should simply
    # be skipped by _detect_indicators rather than crashing discovery.
    assert result["python_files"] == 2
    assert result["flask_indicators"]["flask"] is True


def test_missing_project_raises_file_not_found(
    tmp_path: Path,
) -> None:
    """A nonexistent project path should raise FileNotFoundError."""

    missing = tmp_path / "does-not-exist"

    try:
        discover_flask_project(str(missing))
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Expected FileNotFoundError")


def test_file_path_raises_not_a_directory(
    tmp_path: Path,
) -> None:
    """A file passed as the project path should be rejected."""

    file_path = write_file(
        tmp_path,
        "not-a-project.txt",
        "hello",
    )

    try:
        discover_flask_project(str(file_path))
    except NotADirectoryError:
        pass
    else:
        raise AssertionError("Expected NotADirectoryError")
