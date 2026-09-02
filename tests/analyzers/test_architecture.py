"""Tests for the Flask-architecture analyzer."""

from __future__ import annotations

from pathlib import Path

from flask_production_mcp.analyzers.architecture import analyze_architecture


def _write(project: Path, rel: str, content: str) -> None:
    path = project / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _ids(project: Path) -> list[str]:
    return sorted(f.id for f in analyze_architecture(project))


def test_clean_factory_project_has_no_findings(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/extensions.py",
        "from flask_sqlalchemy import SQLAlchemy\n"
        "from flask_migrate import Migrate\n"
        "db = SQLAlchemy()\n"
        "migrate = Migrate()\n",
    )
    _write(
        tmp_path,
        "app/__init__.py",
        "from flask import Flask\n"
        "from app.extensions import db, migrate\n\n"
        "def create_app():\n"
        "    app = Flask(__name__)\n"
        "    db.init_app(app)\n"
        "    migrate.init_app(app, db)\n"
        "    return app\n",
    )

    assert analyze_architecture(tmp_path) == []


def test_flags_import_time_extension_binding(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/extensions.py",
        "from flask import Flask\n"
        "from flask_sqlalchemy import SQLAlchemy\n"
        "app = Flask(__name__)\n"
        "db = SQLAlchemy(app)\n",
    )

    assert "ARCH-EXT-001" in _ids(tmp_path)


def test_limiter_with_keyfunc_only_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/extensions.py",
        "from flask_limiter import Limiter\n"
        "from flask_limiter.util import get_remote_address\n"
        "limiter = Limiter(key_func=get_remote_address)\n",
    )

    assert "ARCH-EXT-001" not in _ids(tmp_path)


def test_flags_module_level_flask_with_factory(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/__init__.py",
        "from flask import Flask\n\n"
        "app = Flask(__name__)\n\n"
        "def create_app():\n"
        "    return Flask(__name__)\n",
    )

    assert "ARCH-FACTORY-001" in _ids(tmp_path)


def test_flags_hardcoded_secret_fallback(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "config.py",
        "import os\n"
        "SECRET_KEY = os.environ.get('SECRET_KEY', 'super-secret-fallback')\n",
    )

    assert "ARCH-SEC-001" in _ids(tmp_path)


def test_placeholder_secret_fallback_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "config.py",
        "import os\n"
        "SECRET_KEY = os.environ.get('SECRET_KEY', 'change-me')\n",
    )

    assert "ARCH-SEC-001" not in _ids(tmp_path)


def test_flags_create_all_in_request_code(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/web.py",
        "from app.extensions import db\n\n"
        "def index():\n"
        "    db.create_all()\n"
        "    return 'ok'\n",
    )

    assert "ARCH-DB-001" in _ids(tmp_path)


def test_create_all_in_init_db_command_is_allowed(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/cli.py",
        "from app.extensions import db\n\n"
        "def init_db():\n"
        "    db.create_all()\n",
    )

    assert "ARCH-DB-001" not in _ids(tmp_path)


def test_flags_unguarded_app_run(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "server.py",
        "from app import create_app\n"
        "app = create_app()\n"
        "app.run()\n",
    )

    assert "ARCH-RUN-001" in _ids(tmp_path)


def test_guarded_app_run_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "run.py",
        "from app import create_app\n"
        "app = create_app()\n"
        'if __name__ == "__main__":\n'
        "    app.run()\n",
    )

    assert "ARCH-RUN-001" not in _ids(tmp_path)


def test_flags_unregistered_blueprint(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/shop/__init__.py",
        "from flask import Blueprint\n"
        "shop_bp = Blueprint('shop', __name__)\n",
    )
    _write(
        tmp_path,
        "app/__init__.py",
        "from flask import Flask\n"
        "from app.shop import shop_bp\n\n"
        "def create_app():\n"
        "    app = Flask(__name__)\n"
        "    return app\n",
    )

    assert "ARCH-BP-001" in _ids(tmp_path)


def test_registered_blueprint_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/shop/__init__.py",
        "from flask import Blueprint\n"
        "shop_bp = Blueprint('shop', __name__)\n",
    )
    _write(
        tmp_path,
        "app/__init__.py",
        "from flask import Flask\n"
        "from app.shop import shop_bp\n\n"
        "def create_app():\n"
        "    app = Flask(__name__)\n"
        "    app.register_blueprint(shop_bp)\n"
        "    return app\n",
    )

    assert "ARCH-BP-001" not in _ids(tmp_path)
