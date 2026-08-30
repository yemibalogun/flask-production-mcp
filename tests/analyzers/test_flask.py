"""Tests for Flask project discovery."""

from __future__ import annotations

from pathlib import Path

from flask_production_mcp.analyzers.flask import (
    discover_flask_project,
    _detect_architecture
)

from flask_production_mcp.models.findings import Severity, Confidence
from flask_production_mcp.analyzers.flask import (
    _detect_debug_configuration,
    _detect_route_conflicts,
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

def test_detects_application_factory(
    tmp_path: Path,
) -> None:
    """The analyzer should detect a conventional Flask application factory."""

    write_file(
        tmp_path,
        "app/__init__.py",
        """
from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)
    return app
""",
    )

    result = discover_flask_project(str(tmp_path))

    architecture = result["flask_architecture"]

    assert architecture["application_factory"] is True
    assert architecture["factory_functions"] == ["create_app"]


def test_detects_flask_blueprints(
    tmp_path: Path,
) -> None:
    """The analyzer should discover Blueprint declarations statically."""

    write_file(
        tmp_path,
        "app/auth/routes.py",
        """
from flask import Blueprint

auth_bp = Blueprint("auth", __name__)
""",
    )

    write_file(
        tmp_path,
        "app/admin/routes.py",
        """
from flask import Blueprint

admin_bp = Blueprint("admin", __name__)
""",
    )

    result = discover_flask_project(str(tmp_path))

    architecture = result["flask_architecture"]

    assert architecture["blueprints"] == [
        {
            "name": "admin",
            "variable": "admin_bp",
            "file": str(
                (tmp_path / "app/admin/routes.py").resolve()
            ),
        },
        {
            "name": "auth",
            "variable": "auth_bp",
            "file": str(
                (tmp_path / "app/auth/routes.py").resolve()
            ),
        },
    ]


def test_handles_projects_without_application_factory(
    tmp_path: Path,
) -> None:
    """Projects using a module-level Flask instance should remain valid."""

    write_file(
        tmp_path,
        "app.py",
        """
from flask import Flask

app = Flask(__name__)
""",
    )

    result = discover_flask_project(str(tmp_path))

    architecture = result["flask_architecture"]

    assert architecture["application_factory"] is False
    assert architecture["factory_functions"] == []
    assert architecture["blueprints"] == []

def test_detects_application_routes(
    tmp_path: Path,
) -> None:
    """The analyzer should discover routes registered with @app.route()."""

    write_file(
        tmp_path,
        "app.py",
        """
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "Hello"


@app.route("/users/<int:user_id>", methods=["GET", "POST"])
def user_detail(user_id):
    return str(user_id)
""",
    )

    result = discover_flask_project(str(tmp_path))

    routes = result["flask_architecture"]["routes"]

    assert routes == [
        {
            "path": "/",
            "methods": ["GET"],
            "endpoint": "index",
            "file": str((tmp_path / "app.py").resolve()),
            "line": 7,
            "blueprint": None,
            "registration_prefix": "",
            "full_path": "/",
        },
        {
            "path": "/users/<int:user_id>",
            "methods": ["GET", "POST"],
            "endpoint": "user_detail",
            "file": str((tmp_path / "app.py").resolve()),
            "line": 12,
            "blueprint": None,
            "registration_prefix": "",
            "full_path": "/users/<int:user_id>",
        },
    ]


def test_detects_blueprint_routes(
    tmp_path: Path,
) -> None:
    """The analyzer should associate @blueprint.route() with its Blueprint."""

    write_file(
        tmp_path,
        "app/auth/routes.py",
        """
from flask import Blueprint

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    return "Login"


@auth_bp.route("/logout")
def logout():
    return "Logout"
""",
    )

    result = discover_flask_project(str(tmp_path))

    routes = result["flask_architecture"]["routes"]

    assert routes == [
        {
            "path": "/login",
            "methods": ["GET", "POST"],
            "endpoint": "login",
            "file": str((tmp_path / "app/auth/routes.py").resolve()),
            "line": 7,
            "blueprint": "auth",
            "registration_prefix": None,
            "full_path": "/login",
        },
        {
            "path": "/logout",
            "methods": ["GET"],
            "endpoint": "logout",
            "file": str((tmp_path / "app/auth/routes.py").resolve()),
            "line": 12,
            "blueprint": "auth",
            "registration_prefix": None,
            "full_path": "/logout",
        },
    ]


def test_handles_route_without_explicit_methods(
    tmp_path: Path,
) -> None:
    """A route without methods should default to Flask's GET behavior."""

    write_file(
        tmp_path,
        "app.py",
        """
from flask import Flask

app = Flask(__name__)


@app.route("/health")
def health():
    return "ok"
""",
    )

    result = discover_flask_project(str(tmp_path))

    routes = result["flask_architecture"]["routes"]

    assert len(routes) == 1
    assert routes[0]["path"] == "/health"
    assert routes[0]["methods"] == ["GET"]
    assert routes[0]["endpoint"] == "health"


def test_detect_architecture_discovers_blueprint_routes_across_files(
    tmp_path: Path,
) -> None:
    """Blueprint declarations in __init__.py must resolve routes in routes.py."""

    package = tmp_path / "shop"
    package.mkdir()

    (package / "__init__.py").write_text(
        """
from flask import Blueprint

shop_bp = Blueprint("shop", __name__)
""",
        encoding="utf-8",
    )

    (package / "routes.py").write_text(
        """
from . import shop_bp

@shop_bp.route("/")
def index():
    return "ok"

@shop_bp.route("/products", methods=["GET", "POST"])
def products():
    return "ok"
""",
        encoding="utf-8",
    )

    result = _detect_architecture(
        [
            package / "routes.py",
            package / "__init__.py",
        ]
    )

    assert result["blueprints"] == [
        {
            "name": "shop",
            "variable": "shop_bp",
            "file": str((package / "__init__.py").resolve()),
        }
    ]

    assert result["routes"] == [
        {
            "path": "/",
            "methods": ["GET"],
            "endpoint": "index",
            "file": str((package / "routes.py").resolve()),
            "line": 4,
            "blueprint": "shop",
            "registration_prefix": None,
            "full_path": "/",
        },
        {
            "path": "/products",
            "methods": ["GET", "POST"],
            "endpoint": "products",
            "file": str((package / "routes.py").resolve()),
            "line": 8,
            "blueprint": "shop",
            "registration_prefix": None,
            "full_path": "/products",
        },
    ]

def test_detect_route_http_shortcuts(tmp_path: Path) -> None:
    """Flask HTTP shortcut decorators should produce the correct method."""

    source_file = tmp_path / "routes.py"

    source_file.write_text(
        """
from flask import Blueprint

api_bp = Blueprint("api", __name__)

@api_bp.get("/get")
def get_route():
    return "ok"

@api_bp.post("/post")
def post_route():
    return "ok"

@api_bp.put("/put")
def put_route():
    return "ok"

@api_bp.patch("/patch")
def patch_route():
    return "ok"

@api_bp.delete("/delete")
def delete_route():
    return "ok"
""",
        encoding="utf-8",
    )

    result = _detect_architecture([source_file])

    routes = {
        route["path"]: route["methods"]
        for route in result["routes"]
    }

    assert routes == {
        "/get": ["GET"],
        "/post": ["POST"],
        "/put": ["PUT"],
        "/patch": ["PATCH"],
        "/delete": ["DELETE"],
    }

def test_detects_blueprint_registration_with_url_prefix(tmp_path: Path) -> None:
    source = """
from flask import Blueprint, Flask

admin_bp = Blueprint("admin", __name__)

@admin_bp.route("/products")
def products():
    return "products"

def create_app():
    app = Flask(__name__)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    return app
"""

    source_file = tmp_path / "app.py"
    source_file.write_text(source, encoding="utf-8")

    architecture = _detect_architecture([source_file])

    assert architecture["blueprint_registrations"] == [
        {
            "blueprint": "admin",
            "variable": "admin_bp",
            "url_prefix": "/admin",
            "file": str(source_file.resolve()),
            "line": 12,
        }
    ]
    

def test_resolves_effective_blueprint_route_path(tmp_path: Path) -> None:
    source = """
from flask import Blueprint, Flask

admin_bp = Blueprint("admin", __name__)

@admin_bp.route("/products")
def products():
    return "products"

def create_app():
    app = Flask(__name__)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    return app
"""

    source_file = tmp_path / "app.py"
    source_file.write_text(source, encoding="utf-8")

    architecture = _detect_architecture([source_file])

    route = next(
        route
        for route in architecture["routes"]
        if route["endpoint"] == "products"
    )

    assert route["path"] == "/products"
    assert route["blueprint"] == "admin"
    assert route["registration_prefix"] == "/admin"
    assert route["full_path"] == "/admin/products"

def test_blueprint_registration_without_prefix(tmp_path: Path) -> None:
    source = """
from flask import Blueprint, Flask

shop_bp = Blueprint("shop", __name__)

@shop_bp.route("/products")
def products():
    return "products"

def create_app():
    app = Flask(__name__)
    app.register_blueprint(shop_bp)
    return app
"""

    source_file = tmp_path / "app.py"
    source_file.write_text(source, encoding="utf-8")

    architecture = _detect_architecture([source_file])

    route = next(
        route
        for route in architecture["routes"]
        if route["endpoint"] == "products"
    )

    assert route["full_path"] == "/products"
    assert route["registration_prefix"] == ""



def test_detects_debug_mode_enabled_via_app_run(
    tmp_path: Path,
) -> None:
    """debug=True passed to app.run() should produce a Flask finding."""

    source_file = write_file(
        tmp_path,
        "app.py",
        """
from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    app.run(debug=True)
""",
    )

    findings = _detect_debug_configuration([source_file])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.id == "FLASK-CONFIG-001"
    assert finding.category == "flask"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.HIGH
    assert finding.file == str(source_file.resolve())
    assert finding.line is not None
    assert finding.metadata["detection"] == "app_run_debug"


def test_detects_app_debug_assignment(
    tmp_path: Path,
) -> None:
    """Explicit app.debug=True should produce a Flask finding."""

    source_file = write_file(
        tmp_path,
        "app.py",
        """
from flask import Flask

app = Flask(__name__)
app.debug = True
""",
    )

    findings = _detect_debug_configuration([source_file])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.id == "FLASK-CONFIG-001"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.HIGH
    assert finding.metadata["detection"] == "app_debug_assignment"


def test_detects_debug_config_assignment(
    tmp_path: Path,
) -> None:
    """app.config['DEBUG']=True should produce a Flask finding."""

    source_file = write_file(
        tmp_path,
        "config.py",
        """
from flask import Flask

app = Flask(__name__)
app.config["DEBUG"] = True
""",
    )

    findings = _detect_debug_configuration([source_file])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.id == "FLASK-CONFIG-001"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.HIGH
    assert finding.metadata["detection"] == "config_debug_assignment"


def test_does_not_flag_debug_value_from_environment(
    tmp_path: Path,
) -> None:
    """
    Environment-controlled DEBUG values should not be treated as a definite
    production misconfiguration because static analysis cannot know the
    runtime environment value.
    """

    source_file = write_file(
        tmp_path,
        "config.py",
        """
import os

DEBUG = os.getenv("DEBUG", "false").lower() == "true"
""",
    )

    findings = _detect_debug_configuration([source_file])

    assert findings == []


def test_detects_module_level_debug_constant(
    tmp_path: Path,
) -> None:
    """A literal DEBUG=True configuration should produce a finding."""

    source_file = write_file(
        tmp_path,
        "config.py",
        """
DEBUG = True
""",
    )

    findings = _detect_debug_configuration([source_file])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.id == "FLASK-CONFIG-001"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.HIGH
    assert finding.metadata["detection"] == "debug_constant"


def test_debug_detection_handles_malformed_python_safely(
    tmp_path: Path,
) -> None:
    """A malformed file must not abort the debug detector."""

    source_file = write_file(
        tmp_path,
        "broken.py",
        """
from flask import Flask

app = Flask(__name__
app.run(debug=True)
""",
    )

    findings = _detect_debug_configuration([source_file])

    assert findings == []

def test_detects_duplicate_flask_routes(tmp_path: Path) -> None:
    """Two routes with the same path and HTTP method should be reported."""

    source_file = write_file(
        tmp_path,
        "app.py",
        """
from flask import Flask

app = Flask(__name__)


@app.get("/users")
def users_one():
    return "one"


@app.get("/users")
def users_two():
    return "two"
""",
    )

    findings = _detect_route_conflicts([source_file])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.id == "FLASK-ROUTE-001"
    assert finding.category == "flask"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.HIGH

    assert finding.file == str(source_file.resolve())
    assert finding.metadata["path"] == "/users"
    assert finding.metadata["method"] == "GET"
    assert finding.metadata["conflict_type"] == "duplicate_route"
    assert finding.metadata["endpoint"] == "users_two"


def test_does_not_flag_same_path_with_different_methods(
    tmp_path: Path,
) -> None:
    """Different HTTP methods on the same path are normally legitimate."""

    source_file = write_file(
        tmp_path,
        "app.py",
        """
from flask import Flask

app = Flask(__name__)


@app.get("/users")
def get_users():
    return "get"


@app.post("/users")
def create_user():
    return "post"
""",
    )

    findings = _detect_route_conflicts([source_file])

    assert findings == []


def test_detects_duplicate_route_across_blueprints(
    tmp_path: Path,
) -> None:
    """Duplicate effective routes should be detected across Blueprints."""

    source_file = write_file(
        tmp_path,
        "app.py",
        """
from flask import Blueprint, Flask

app = Flask(__name__)

admin_bp = Blueprint("admin", __name__)
shop_bp = Blueprint("shop", __name__)


@admin_bp.get("/dashboard")
def admin_dashboard():
    return "admin"


@shop_bp.get("/dashboard")
def shop_dashboard():
    return "shop"


app.register_blueprint(admin_bp, url_prefix="/admin")
app.register_blueprint(shop_bp, url_prefix="/admin")
""",
    )

    findings = _detect_route_conflicts([source_file])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.id == "FLASK-ROUTE-001"
    assert finding.metadata["path"] == "/admin/dashboard"
    assert finding.metadata["method"] == "GET"
    assert finding.metadata["conflict_type"] == "duplicate_route"
    assert finding.metadata["endpoint"] == "shop_dashboard"


def test_detects_duplicate_route_with_route_decorator(
    tmp_path: Path,
) -> None:
    """The generic @app.route decorator should participate in conflict detection."""

    source_file = write_file(
        tmp_path,
        "app.py",
        """
from flask import Flask

app = Flask(__name__)


@app.route("/health")
def health_one():
    return "one"


@app.route("/health")
def health_two():
    return "two"
""",
    )

    findings = _detect_route_conflicts([source_file])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.metadata["path"] == "/health"
    assert finding.metadata["method"] == "GET"


def test_duplicate_route_detection_handles_malformed_python_safely(
    tmp_path: Path,
) -> None:
    """A malformed file should not abort route conflict analysis."""

    source_file = write_file(
        tmp_path,
        "broken.py",
        """
def broken(
""",
    )

    findings = _detect_route_conflicts([source_file])

    assert findings == []