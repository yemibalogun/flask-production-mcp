"""Shared fixtures for MCP tool tests."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest


@pytest.fixture
def flawed_flask_project(tmp_path: Path) -> Path:
    """
    Create a small Flask project that deliberately contains one issue for
    every analyzer so end-to-end tool behavior can be asserted.
    """

    project = tmp_path / "sample_app"
    app_pkg = project / "app"
    app_pkg.mkdir(parents=True)

    (project / "requirements.txt").write_text(
        "flask\nflask-sqlalchemy\n",
        encoding="utf-8",
    )

    (app_pkg / "__init__.py").write_text("", encoding="utf-8")

    # Flask issues: debug mode enabled + a duplicate route.
    (app_pkg / "main.py").write_text(
        dedent(
            '''
            from flask import Flask, request

            app = Flask(__name__)


            @app.route("/users", methods=["GET"])
            def list_users():
                return "users"


            @app.route("/users", methods=["GET"])
            def list_users_again():
                return "users again"


            @app.route("/run")
            def run_code():
                return eval(request.args["expr"])


            if __name__ == "__main__":
                app.run(debug=True)
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    # Security issue: a hardcoded production secret.
    (app_pkg / "config.py").write_text(
        dedent(
            '''
            SECRET_KEY = "super-secret-production-value-9f8e7d6c5b4a"
            SQLALCHEMY_DATABASE_URI = "postgresql://localhost/app"
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    # Database issue: raw SQL execution.
    (app_pkg / "models.py").write_text(
        dedent(
            '''
            from flask_sqlalchemy import SQLAlchemy

            db = SQLAlchemy()


            class User(db.Model):
                __tablename__ = "users"

                id = db.Column(db.Integer, primary_key=True)
                email = db.Column(db.String(255))


            def recent_signups():
                return db.session.execute("SELECT * FROM users LIMIT 10")
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    # Code-quality issues: print(), bare except, assert in app code.
    (app_pkg / "utils.py").write_text(
        dedent(
            '''
            def process(value):
                assert value is not None

                try:
                    print(value)
                except:
                    pass

                return value
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    # A test module - the code-quality audit must ignore its assert.
    tests_dir = project / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_utils.py").write_text(
        "def test_process():\n    assert True\n",
        encoding="utf-8",
    )

    return project
