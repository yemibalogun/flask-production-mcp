"""Flask-specific architecture checks.

Generic Python SAST does not understand the Flask application factory,
blueprint registration, or extension lifecycle. These rules encode the
mistakes that break multi-instance testing, leak development configuration
into production, or run the development server on import.

All analysis is static AST inspection; the target app is never imported.
"""

from __future__ import annotations

import ast
from pathlib import Path

from flask_production_mcp.analyzers.exclusions import iter_python_files
from flask_production_mcp.models.findings import (
    Confidence,
    Finding,
    Severity,
)

# Flask extension classes that follow the init_app() lifecycle. Binding one
# of these to an app at import time defeats the application-factory pattern.
_EXTENSION_CLASSES: frozenset[str] = frozenset(
    {
        "SQLAlchemy",
        "Migrate",
        "LoginManager",
        "Mail",
        "CSRFProtect",
        "Cache",
        "Limiter",
        "Bcrypt",
        "JWTManager",
        "Marshmallow",
        "CORS",
        "Session",
        "Babel",
        "SocketIO",
        "Admin",
        "DebugToolbarExtension",
        "Moment",
        "Compress",
        "Talisman",
    }
)

_FACTORY_NAMES: frozenset[str] = frozenset(
    {"create_app", "create_application", "make_app", "make_application"}
)

_PLACEHOLDER_SECRET = {
    "",
    "change-me",
    "changeme",
    "your-secret-key",
    "your-secret-key-here",
    "secret",
    "please-change",
    "replace-me",
}


def _module_level_nodes(tree: ast.Module):
    """Yield statements that execute at import time (module body + guards)."""

    for node in tree.body:
        yield node
        # Statements inside a top-level if/try still run on import.
        if isinstance(node, (ast.If, ast.Try, ast.With)):
            for child in ast.walk(node):
                if child is not node:
                    yield child


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
    return None


def _is_name(node: ast.AST, name: str) -> bool:
    return isinstance(node, ast.Name) and node.id == name


def _binds_app(call: ast.Call) -> bool:
    """True when an extension constructor is passed an app to bind to."""

    for keyword in call.keywords:
        if keyword.arg in {"app", "application"}:
            return True
    for arg in call.args:
        if _is_name(arg, "app") or _is_name(arg, "application"):
            return True
        if isinstance(arg, ast.Call) and _call_name(arg) == "Flask":
            return True
    return False


def _string_literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _guarded_by_main(tree: ast.Module, target: ast.AST) -> bool:
    """True when ``target`` is inside an ``if __name__ == "__main__"`` block."""

    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        is_main_guard = (
            isinstance(test, ast.Compare)
            and _is_name(test.left, "__name__")
            and len(test.comparators) == 1
            and _string_literal(test.comparators[0]) == "__main__"
        )
        if not is_main_guard:
            continue
        for child in ast.walk(node):
            if child is target:
                return True
    return False


def _find_import_time_extension_binding(
    file_path: Path, tree: ast.Module
) -> list[Finding]:
    findings: list[Finding] = []

    for node in _module_level_nodes(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        name = _call_name(value)
        if name not in _EXTENSION_CLASSES:
            continue
        if not _binds_app(value):
            continue

        findings.append(
            Finding(
                id="ARCH-EXT-001",
                category="architecture",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title=f"{name} is bound to an app at import time",
                description=(
                    f"{name}(...) is called with an app object at module "
                    "scope. This defeats the application-factory pattern: "
                    "the extension is permanently tied to one app instance, "
                    "so a second instance (e.g. the test suite) shares or "
                    "fights over its state."
                ),
                recommendation=(
                    f"Create the extension unbound at module scope "
                    f"(`{name.lower()} = {name}()`) and attach it inside "
                    "create_app() with `.init_app(app)`."
                ),
                file=str(file_path),
                line=node.lineno,
                metadata={"extension": name},
            )
        )

    return findings


def _find_module_level_flask_with_factory(
    file_path: Path, tree: ast.Module, factory_exists: bool
) -> list[Finding]:
    if not factory_exists:
        return []

    findings: list[Finding] = []

    for node in _module_level_nodes(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if not (isinstance(value, ast.Call) and _call_name(value) == "Flask"):
            continue

        findings.append(
            Finding(
                id="ARCH-FACTORY-001",
                category="architecture",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title="Module-level Flask() app alongside an app factory",
                description=(
                    "This module creates a Flask app at import time even "
                    "though the project defines a create_app() factory. The "
                    "global app captures configuration and imports at the "
                    "wrong time and is easy to import by accident."
                ),
                recommendation=(
                    "Build the app only through create_app(). Entry points "
                    "(wsgi.py, run.py) should call the factory, not "
                    "instantiate Flask() directly."
                ),
                file=str(file_path),
                line=node.lineno,
                metadata={},
            )
        )

    return findings


def _find_hardcoded_secret_fallback(
    file_path: Path, tree: ast.Module
) -> list[Finding]:
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _call_name(node) not in {"get", "getenv"}:
            continue
        if len(node.args) < 2:
            continue

        key = _string_literal(node.args[0])
        fallback = _string_literal(node.args[1])
        if key is None or fallback is None:
            continue
        if "SECRET" not in key.upper() and "KEY" not in key.upper():
            continue
        if fallback.strip().lower() in _PLACEHOLDER_SECRET:
            continue
        if len(fallback) < 8:
            continue

        findings.append(
            Finding(
                id="ARCH-SEC-001",
                category="architecture",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title=f"Hardcoded fallback for {key}",
                description=(
                    f"os.environ.get('{key}', ...) falls back to a "
                    "hardcoded string. If the environment variable is ever "
                    "unset in production the app silently runs with a known, "
                    "committed secret - which is equivalent to having no "
                    "secret at all."
                ),
                recommendation=(
                    f"Drop the fallback and fail loudly when {key} is "
                    "missing (e.g. raise RuntimeError in a production "
                    "config check), so a misconfigured deploy stops instead "
                    "of running insecurely."
                ),
                file=str(file_path),
                line=node.lineno,
                metadata={"config_key": key},
            )
        )

    return findings


def _find_create_all_misuse(
    file_path: Path, tree: ast.Module
) -> list[Finding]:
    findings: list[Finding] = []

    # Functions whose name marks them as CLI/setup code, where create_all
    # is acceptable.
    allowed_scopes = {
        "init_db",
        "initdb",
        "create_db",
        "createdb",
        "setup_db",
        "seed",
        "seed_db",
        "bootstrap",
    }

    def scope_ok(stack: list[str]) -> bool:
        return any(s in allowed_scopes for s in stack)

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stack: list[str] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

        def visit_Call(self, node: ast.Call) -> None:
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "create_all"
                and not scope_ok(self.stack)
            ):
                findings.append(
                    Finding(
                        id="ARCH-DB-001",
                        category="architecture",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        title="db.create_all() outside migration/CLI code",
                        description=(
                            "create_all() only creates tables that do not "
                            "exist yet - it never applies schema changes. "
                            "Relying on it in app startup or request code "
                            "hides migrations and drifts environments apart."
                        ),
                        recommendation=(
                            "Manage schema with Flask-Migrate/Alembic "
                            "(`flask db upgrade`). Keep create_all() to "
                            "tests and one-off local setup commands."
                        ),
                        file=str(file_path),
                        line=node.lineno,
                        metadata={"scope": "/".join(self.stack) or "<module>"},
                    )
                )
            self.generic_visit(node)

    Visitor().visit(tree)
    return findings


def _find_unguarded_app_run(
    file_path: Path, tree: ast.Module
) -> list[Finding]:
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "run"):
            continue
        # `app.run` / `application.run` - keep the false-positive rate low.
        if not (
            isinstance(func.value, ast.Name)
            and func.value.id in {"app", "application"}
        ):
            continue
        if _guarded_by_main(tree, node):
            continue

        findings.append(
            Finding(
                id="ARCH-RUN-001",
                category="architecture",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title="app.run() is not guarded by __main__",
                description=(
                    "app.run() executes as soon as this module is "
                    "imported. Anything that imports it (a WSGI server, a "
                    "test, a CLI) starts the single-threaded development "
                    "server."
                ),
                recommendation=(
                    'Move app.run() under `if __name__ == "__main__":` and '
                    "serve production traffic with Gunicorn/uWSGI via "
                    "wsgi.py."
                ),
                file=str(file_path),
                line=node.lineno,
                metadata={},
            )
        )

    return findings


def _find_unregistered_blueprints(
    files: list[Path],
) -> list[Finding]:
    """Blueprints that are defined but never registered anywhere."""

    from flask_production_mcp.analyzers.flask import _detect_architecture

    architecture = _detect_architecture(files)

    registered = {
        registration["blueprint"]
        for registration in architecture.get("blueprint_registrations", [])
    }

    findings: list[Finding] = []
    for blueprint in architecture.get("blueprints", []):
        if blueprint["name"] in registered:
            continue

        findings.append(
            Finding(
                id="ARCH-BP-001",
                category="architecture",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                title=f"Blueprint '{blueprint['name']}' is never registered",
                description=(
                    f"The blueprint '{blueprint['name']}' is created but no "
                    "app.register_blueprint() call for it was found. Its "
                    "routes are unreachable (or it is registered dynamically "
                    "in a way static analysis cannot see)."
                ),
                recommendation=(
                    "Register the blueprint in create_app(), or remove it "
                    "if it is dead code."
                ),
                file=blueprint.get("file"),
                line=None,
                metadata={"blueprint": blueprint["name"]},
            )
        )

    return findings


def analyze_architecture(project_path: str | Path) -> list[Finding]:
    """Run every Flask-architecture rule against a project."""

    root = Path(project_path).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError(
            f"Architecture analysis root is invalid: {root}"
        )

    files = list(iter_python_files(root, include_tests=False))

    parsed: list[tuple[Path, ast.Module]] = []
    for file_path in files:
        try:
            source = file_path.read_text(
                encoding="utf-8-sig", errors="replace"
            )
            parsed.append((file_path, ast.parse(source, str(file_path))))
        except (OSError, SyntaxError):
            continue

    factory_exists = any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in _FACTORY_NAMES
        for _, tree in parsed
        for node in ast.walk(tree)
    )

    findings: list[Finding] = []
    for file_path, tree in parsed:
        findings.extend(
            _find_import_time_extension_binding(file_path, tree)
        )
        findings.extend(
            _find_module_level_flask_with_factory(
                file_path, tree, factory_exists
            )
        )
        findings.extend(_find_hardcoded_secret_fallback(file_path, tree))
        findings.extend(_find_create_all_misuse(file_path, tree))
        findings.extend(_find_unguarded_app_run(file_path, tree))

    findings.extend(_find_unregistered_blueprints(files))

    return findings
