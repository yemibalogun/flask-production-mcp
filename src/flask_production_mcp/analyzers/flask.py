"""Flask project discovery and architecture analysis."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.base import build_audit_result
from flask_production_mcp.analyzers.exclusions import (
    DEFAULT_EXCLUDED_DIRECTORIES,
)
from flask_production_mcp.models.findings import (
    AuditResult,
    Confidence,
    Finding,
    Severity,
)

# Directories that normally contain generated dependencies, caches, or
# version-control data. Traversing these would dramatically increase audit
# time and could produce thousands of irrelevant files. The shared exclusion
# set is reused so every analyzer skips the same directories.
IGNORED_DIRECTORIES: frozenset[str] = DEFAULT_EXCLUDED_DIRECTORIES

# Flask exposes both the generic ``.route()`` decorator and HTTP-method
# shortcuts such as ``.get()`` and ``.post()``. Keeping these in one place
# prevents route discovery from silently ignoring valid Flask routes.
FLASK_ROUTE_DECORATORS = {
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
}


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

    architecture = _detect_architecture(python_files)

    return {
        "project_path": str(root),
        "python_files": len(python_files),
        "template_files": len(template_files),
        "static_files": len(static_files),
        "directories": _discover_directories(root),
        "flask_indicators": indicators,
        "flask_architecture": architecture,
    }

def _collect_python_files(root: Path) -> list[Path]:
    """Return every Flask application Python file under ``root``."""

    python_files: list[Path] = []

    for path in root.rglob("*.py"):
        if any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue

        if path.is_file():
            python_files.append(path)

    return python_files


def analyze_flask(project_path: str | Path) -> AuditResult:
    """
    Audit a Flask application's architecture for production-readiness issues.

    This complements :func:`discover_flask_project` (which only describes the
    application) by returning structured findings and a score. Detected
    issues currently include:

    - explicitly enabled debug mode
    - duplicate routes that resolve to the same method and path

    The target application is never imported or executed.
    """

    root = Path(project_path).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Project path does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Project path is not a directory: {root}")

    python_files = _collect_python_files(root)

    findings: list[Finding] = []
    findings.extend(_detect_debug_configuration(python_files))
    findings.extend(_detect_route_conflicts(python_files))

    return build_audit_result(root, findings)


def _detect_architecture(
    python_files: list[Path],
) -> dict[str, Any]:
    """
    Detect the high-level Flask application architecture.

    Route declarations and Blueprint registrations are discovered separately.
    This is important because a Blueprint's effective URL cannot be known from
    the route decorator alone; the prefix is applied when the Blueprint is
    registered with the Flask application.
    """
    factory_functions: list[str] = []
    blueprints: list[dict[str, str]] = []
    routes: list[dict[str, Any]] = []
    blueprint_registrations: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Pass 1: parse every Python file once.
    #
    # Keeping the ASTs in memory allows us to perform multiple discovery
    # passes without repeatedly reading/parsing the same source files.
    # ------------------------------------------------------------------
    parsed_files: list[tuple[Path, ast.AST]] = []

    for source_file in python_files:
        try:
            source = source_file.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )
            parsed_tree: ast.AST = ast.parse(source)
        except (OSError, SyntaxError):
            # A single malformed/unreadable source file should not prevent
            # analysis of the remainder of the application.
            continue

        parsed_files.append((source_file, parsed_tree))

    # ------------------------------------------------------------------
    # Pass 2: discover Blueprint declarations and application factories.
    # ------------------------------------------------------------------
    for source_file, tree in parsed_files:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                _detect_blueprint_assignment(
                    node=node,
                    source_file=source_file,
                    blueprints=blueprints,
                )

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in {"create_app", "create_application"}:
                    factory_functions.append(node.name)

    factory_functions = sorted(set(factory_functions))

    # ------------------------------------------------------------------
    # Pass 3: discover Blueprint registrations.
    #
    # This must happen AFTER all Blueprint declarations have been collected
    # so registrations can be associated with their actual Blueprint names.
    # ------------------------------------------------------------------
    _detect_blueprint_registrations(
        parsed_files=parsed_files,
        blueprints=blueprints,
        registrations=blueprint_registrations,
    )

    # ------------------------------------------------------------------
    # Pass 4: discover route declarations.
    # ------------------------------------------------------------------
    for source_file, tree in parsed_files:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _detect_routes(
                    node=node,
                    source_file=source_file,
                    blueprints=blueprints,
                    routes=routes,
                )

    # ------------------------------------------------------------------
    # Resolve the Blueprint registration prefix onto each discovered route.
    # ------------------------------------------------------------------
    _apply_blueprint_registration_prefixes(
        routes=routes,
        registrations=blueprint_registrations,
        blueprints=blueprints,
    )

    blueprints.sort(
        key=lambda blueprint: (
            blueprint["name"],
            blueprint["file"],
            blueprint["variable"],
        )
    )

    blueprint_registrations.sort(
        key=lambda registration: (
            registration["blueprint"],
            registration["file"],
            registration["line"],
        )
    )

    routes.sort(
        key=lambda route: (
            route["file"],
            route["line"],
            route["path"],
            route["endpoint"],
        )
    )

    return {
        "application_factory": bool(factory_functions),
        "factory_functions": factory_functions,
        "blueprints": blueprints,
        "blueprint_registrations": blueprint_registrations,
        "routes": routes,
    }


def _detect_blueprint_assignment(
    node: ast.Assign,
    source_file: Path,
    blueprints: list[dict[str, str]],
) -> None:
    """Detect assignments such as ``auth_bp = Blueprint('auth', __name__)``."""

    # A Blueprint declaration should have exactly one assignment target in
    # normal Flask code. Supporting multiple targets would add complexity
    # without improving useful project discovery.
    if len(node.targets) != 1:
        return

    target = node.targets[0]

    if not isinstance(target, ast.Name):
        return

    call = node.value

    if not isinstance(call, ast.Call):
        return

    # We only recognize a direct Blueprint(...) call here. More complex
    # factory wrappers can be supported later once we have explicit tests
    # defining their desired behavior.
    if not isinstance(call.func, ast.Name):
        return

    if call.func.id != "Blueprint":
        return

    if not call.args:
        return

    blueprint_name = call.args[0]

    if not isinstance(blueprint_name, ast.Constant):
        return

    if not isinstance(blueprint_name.value, str):
        return

    blueprints.append(
        {
            "name": blueprint_name.value,
            "variable": target.id,
            "file": str(source_file.resolve()),
            # Flask lets a Blueprint carry its own url_prefix on the
            # constructor. If register_blueprint() does not override it,
            # this is the prefix that actually applies to every route.
            "url_prefix": _extract_url_prefix(call),
        }
    )

def _detect_blueprint_registrations(
    parsed_files: list[tuple[Path, ast.AST]],
    blueprints: list[dict[str, str]],
    registrations: list[dict[str, Any]],
) -> None:
    """
    Detect calls such as:

        app.register_blueprint(admin_bp)

    and:

        app.register_blueprint(
            auth_bp,
            url_prefix="/auth",
        )

    Only statically resolvable Blueprint variables are reported.
    """
    blueprint_names = {
        blueprint["variable"]: blueprint["name"]
        for blueprint in blueprints
    }

    for source_file, tree in parsed_files:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # We are specifically looking for:
            #
            #     something.register_blueprint(...)
            #
            # rather than arbitrary function calls named similarly.
            if not isinstance(node.func, ast.Attribute):
                continue

            if node.func.attr != "register_blueprint":
                continue

            # register_blueprint() requires the Blueprint as its first
            # positional argument in normal Flask usage.
            if not node.args:
                continue

            blueprint_node = node.args[0]

            if not isinstance(blueprint_node, ast.Name):
                # Dynamic expressions such as:
                #
                #     app.register_blueprint(get_blueprint())
                #
                # cannot be safely resolved through this static analyzer.
                continue

            blueprint_variable = blueprint_node.id
            blueprint_name = blueprint_names.get(blueprint_variable)

            if blueprint_name is None:
                # Prevent false positives for arbitrary objects that happen
                # to be passed to register_blueprint().
                continue

            url_prefix = _extract_url_prefix(node)

            registrations.append(
                {
                    "blueprint": blueprint_name,
                    "variable": blueprint_variable,
                    "url_prefix": url_prefix,
                    "file": str(source_file.resolve()),
                    "line": node.lineno,
                }
            )

def _extract_url_prefix(
    registration: ast.Call,
) -> str:
    """
    Extract a statically defined url_prefix from register_blueprint().

    Flask permits many dynamic expressions, but only a literal string can be
    confidently resolved without executing the target application.
    """
    for keyword in registration.keywords:
        if keyword.arg != "url_prefix":
            continue

        value = keyword.value

        if not isinstance(value, ast.Constant):
            return ""

        if not isinstance(value.value, str):
            return ""

        return _normalize_url_prefix(value.value)

    return ""

def _apply_blueprint_registration_prefixes(
    routes: list[dict[str, Any]],
    registrations: list[dict[str, Any]],
    blueprints: list[dict[str, Any]] | None = None,
) -> None:
    """
    Attach Blueprint registration information and effective URL paths
    to discovered routes.

    Routes belonging to a Blueprint may have zero, one, or multiple
    registrations. Flask technically allows the same Blueprint to be
    registered multiple times, potentially with different prefixes.

    A Blueprint can also carry a ``url_prefix`` on its constructor. Flask
    uses the registration-time ``url_prefix`` when one is supplied, and
    otherwise falls back to the constructor prefix, so the effective
    prefix here is ``registration prefix or constructor prefix``.

    Therefore we do not overwrite the original ``path`` field. Instead,
    ``full_path`` represents the effective path when exactly one registration
    can be resolved, while ``registration_prefix`` records the discovered
    prefix.
    """
    registrations_by_blueprint: dict[str, list[dict[str, Any]]] = {}

    for registration in registrations:
        registrations_by_blueprint.setdefault(
            registration["blueprint"],
            [],
        ).append(registration)

    constructor_prefix_by_blueprint: dict[str, str] = {
        blueprint["name"]: blueprint.get("url_prefix", "")
        for blueprint in (blueprints or [])
    }

    for route in routes:
        blueprint = route.get("blueprint")

        if not blueprint:
            # Application-level routes already use their declared path.
            route["registration_prefix"] = ""
            route["full_path"] = route["path"]
            continue

        constructor_prefix = constructor_prefix_by_blueprint.get(
            blueprint,
            "",
        )

        matching_registrations = registrations_by_blueprint.get(
            blueprint,
            []
        )

        if not matching_registrations:
            # No static registration was resolved. The Blueprint's own
            # constructor prefix (if any) still applies in Flask.
            route["registration_prefix"] = (
                constructor_prefix if constructor_prefix else None
            )
            route["full_path"] = _join_route_paths(
                constructor_prefix,
                route["path"],
            )
            continue

        if len(matching_registrations) == 1:
            prefix = (
                matching_registrations[0]["url_prefix"]
                or constructor_prefix
            )

            route["registration_prefix"] = prefix
            route["full_path"] = _join_route_paths(
                prefix,
                route["path"],
            )
            continue

        # A Blueprint registered more than once can legitimately produce
        # multiple effective URLs. Preserve every known possibility.
        full_paths: list[str] = []

        for registration in matching_registrations:
            full_path = _join_route_paths(
                registration["url_prefix"] or constructor_prefix,
                route["path"],
            )

            if full_path not in full_paths:
                full_paths.append(full_path)

        route["registration_prefix"] = None
        route["full_path"] = full_paths

def _join_route_paths(
    prefix: str,
    path: str,
) -> str:
    """
    Join a Blueprint prefix and route path using Flask-style URL semantics.

    Examples:
        /admin + /products -> /admin/products
        /admin + /          -> /admin/
        "" + /products      -> /products
    """
    prefix = prefix.strip()
    path = path.strip()

    if not prefix:
        return path or "/"

    if not path:
        return prefix or "/"

    # Preserve the route's trailing slash when it explicitly has one.
    joined = f"{prefix.rstrip('/')}/{path.lstrip('/')}"

    if path.endswith("/") and not joined.endswith("/"):
        joined += "/"

    return joined

    
def _normalize_url_prefix(value: str) -> str:
    """
    Normalize a Blueprint URL prefix without changing its semantic meaning.

    Examples:
        ""       -> ""
        "/"      -> ""
        "admin"  -> "/admin"
        "/admin/" -> "/admin"
    """
    value = value.strip()

    if not value or value == "/":
        return ""

    return "/" + value.strip("/")

def _detect_routes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    source_file: Path,
    blueprints: list[dict[str, str]],
    routes: list[dict[str, Any]],
) -> None:
    """Detect Flask route decorators attached to a function."""

    # Build a variable -> Blueprint-name lookup from the complete project.
    # Example:
    #     admin_bp = Blueprint("admin", __name__)
    #
    # becomes:
    #     {"admin_bp": "admin"}
    blueprint_names = {
        blueprint["variable"]: blueprint["name"]
        for blueprint in blueprints
    }

    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue

        if not isinstance(decorator.func, ast.Attribute):
            continue

        decorator_name = decorator.func.attr

        # Recognize both:
        #
        #     @bp.route(...)
        #
        # and Flask's HTTP shortcut decorators:
        #
        #     @bp.get(...)
        #     @bp.post(...)
        #     @bp.put(...)
        #     @bp.patch(...)
        #     @bp.delete(...)
        #     @bp.head(...)
        #     @bp.options(...)
        if decorator_name not in FLASK_ROUTE_DECORATORS:
            continue

        route_owner = decorator.func.value

        # We only resolve simple names such as ``admin_bp.route``.
        # Dynamic expressions such as ``get_blueprint().route`` cannot be
        # reliably resolved with this lightweight static analysis.
        if not isinstance(route_owner, ast.Name):
            continue

        route_path = _extract_route_path(decorator)

        if route_path is None:
            continue

        # Determine the explicitly configured HTTP methods.
        #
        # ``@bp.route(...)`` gets its methods from the ``methods=`` argument.
        # Shortcut decorators such as ``@bp.post(...)`` inherently represent
        # one HTTP method and therefore do not need a methods argument.
        methods = _extract_route_methods(
            decorator,
            decorator_name=decorator_name,
        )

        if route_owner.id == "app":
            blueprint = None
        else:
            # Only identify the owner as a Blueprint when we actually found
            # a matching Blueprint declaration. This prevents arbitrary
            # ``something.route()`` decorators from being reported as Flask
            # routes.
            blueprint = blueprint_names.get(route_owner.id)

            if blueprint is None:
                continue

        routes.append(
            {
                "path": route_path,
                "methods": methods,
                "endpoint": node.name,
                "file": str(source_file.resolve()),
                "line": decorator.lineno,
                "blueprint": blueprint,
            }
        )

def _extract_route_path(
    decorator: ast.Call,
) -> str | None:
    """Extract a statically defined route path from a route decorator."""

    if not decorator.args:
        return None

    path_node = decorator.args[0]

    if not isinstance(path_node, ast.Constant):
        return None

    if not isinstance(path_node.value, str):
        return None

    return path_node.value


def _extract_route_methods(
    decorator: ast.Call,
    decorator_name: str = "route",
) -> list[str]:
    """
    Extract HTTP methods represented by a Flask route decorator.

    Generic ``.route()`` decorators use the optional ``methods=`` argument
    and default to GET.

    HTTP shortcut decorators such as ``.post()`` imply their corresponding
    HTTP method directly.
    """

    # Flask's shortcut decorators explicitly represent one HTTP method.
    shortcut_methods = {
        "get": "GET",
        "post": "POST",
        "put": "PUT",
        "patch": "PATCH",
        "delete": "DELETE",
        "head": "HEAD",
        "options": "OPTIONS",
    }

    shortcut_method = shortcut_methods.get(decorator_name)

    if shortcut_method is not None:
        return [shortcut_method]

    # ``@bp.route("/foo")`` defaults to GET.
    for keyword in decorator.keywords:
        if keyword.arg != "methods":
            continue

        value = keyword.value

        # Dynamic expressions such as:
        #
        #     methods=ALLOWED_METHODS
        #
        # cannot be resolved reliably without executing the target project.
        if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return ["GET"]

        methods: list[str] = []

        for element in value.elts:
            if not isinstance(element, ast.Constant):
                continue

            if not isinstance(element.value, str):
                continue

            method = element.value.upper()

            if method not in methods:
                methods.append(method)

        return methods or ["GET"]

    return ["GET"]


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
                encoding="utf-8-sig",
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



# Class-name fragments that identify a configuration class which, by
# convention, is never loaded in production. A literal ``DEBUG = True`` in
# one of these is correct code, not a finding.
_NONPRODUCTION_CONFIG_CLASS_HINTS: tuple[str, ...] = (
    "dev",
    "development",
    "test",
    "testing",
    "local",
    "debug",
)


def _nonproduction_class_line_ranges(
    tree: ast.AST,
) -> list[tuple[int, int]]:
    """Line ranges of classes whose name marks them as dev/test-only config."""

    ranges: list[tuple[int, int]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue

        lowered = node.name.lower()

        if not any(
            hint in lowered for hint in _NONPRODUCTION_CONFIG_CLASS_HINTS
        ):
            continue

        end = getattr(node, "end_lineno", None) or node.lineno
        ranges.append((node.lineno, end))

    return ranges


def _detect_debug_configuration(
    python_files: list[Path],
) -> list[Finding]:
    """
    Detect statically provable Flask debug-mode configuration.

    Only literal ``True`` values are reported. Environment-controlled or
    dynamically computed values are intentionally ignored because static
    analysis cannot determine their production-time value.

    A literal debug assignment inside a class whose name marks it as
    development/testing configuration (e.g. ``DevelopmentConfig``) is
    treated as correct code and skipped. ``app.run(debug=True)`` is always
    reported because it is never production-safe.

    Supported patterns include:

        app.run(debug=True)
        app.debug = True
        app.config["DEBUG"] = True
        DEBUG = True
    """

    findings: list[Finding] = []

    for file_path in python_files:
        try:
            source = file_path.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError):
            # A malformed file should never prevent the remaining project
            # files from being analyzed.
            continue

        skip_ranges = _nonproduction_class_line_ranges(tree)

        for node in ast.walk(tree):

            # -------------------------------------------------------------
            # Pattern 1: app.run(debug=True)
            # -------------------------------------------------------------
            if isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "run"
                ):
                    for keyword in node.keywords:
                        if (
                            keyword.arg == "debug"
                            and isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is True
                        ):
                            findings.append(
                                Finding(
                                    id="FLASK-CONFIG-001",
                                    category="flask",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.HIGH,
                                    title=(
                                        "Flask debug mode is explicitly enabled"
                                    ),
                                    description=(
                                        "The Flask development debug mode "
                                        "is explicitly enabled with "
                                        "debug=True. Debug mode can expose "
                                        "sensitive application information "
                                        "and should not be enabled in "
                                        "production."
                                    ),
                                    recommendation=(
                                        "Disable Flask debug mode in "
                                        "production and keep development "
                                        "settings separate from production "
                                        "configuration."
                                    ),
                                    file=str(file_path.resolve()),
                                    line=node.lineno,
                                    metadata={
                                        "detection": "app_run_debug",
                                    },
                                )
                            )

            if not isinstance(node, ast.Assign):
                continue

            # A literal debug assignment inside a development/testing config
            # class is correct code, so it is not reported.
            if any(
                start <= node.lineno <= end
                for start, end in skip_ranges
            ):
                continue

            # Only simple single-target assignments are considered. This
            # avoids producing ambiguous findings for constructs such as:
            #
            #     DEBUG = OTHER = True
            if len(node.targets) != 1:
                continue

            target = node.targets[0]

            # We only care about the literal boolean True. Expressions such
            # as os.getenv(...) == "true" are intentionally ignored.
            is_true = (
                isinstance(node.value, ast.Constant)
                and node.value.value is True
            )

            if not is_true:
                continue

            # -------------------------------------------------------------
            # Pattern 2: app.debug = True
            # -------------------------------------------------------------
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "debug"
            ):
                findings.append(
                    Finding(
                        id="FLASK-CONFIG-001",
                        category="flask",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title="Flask debug mode is explicitly enabled",
                        description=(
                            "The Flask application debug attribute is "
                            "explicitly assigned True. Debug mode should "
                            "not be enabled in a production deployment."
                        ),
                        recommendation=(
                            "Disable Flask debug mode in production and "
                            "keep development-only settings separate from "
                            "production configuration."
                        ),
                        file=str(file_path.resolve()),
                        line=node.lineno,
                        metadata={
                            "detection": "app_debug_assignment",
                        },
                    )
                )

                # This assignment has already been classified, so don't
                # accidentally classify it as another assignment pattern.
                continue

            # -------------------------------------------------------------
            # Pattern 3: app.config["DEBUG"] = True
            # -------------------------------------------------------------
            if isinstance(target, ast.Subscript):
                if (
                    isinstance(target.value, ast.Attribute)
                    and target.value.attr == "config"
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value == "DEBUG"
                ):
                    findings.append(
                        Finding(
                            id="FLASK-CONFIG-001",
                            category="flask",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            title="Flask debug mode is explicitly enabled",
                            description=(
                                "The Flask DEBUG configuration is explicitly "
                                "set to True. This can expose sensitive "
                                "application information in production."
                            ),
                            recommendation=(
                                "Disable DEBUG in production configuration "
                                "and use environment-specific configuration "
                                "for development settings."
                            ),
                            file=str(file_path.resolve()),
                            line=node.lineno,
                            metadata={
                                "detection": "config_debug_assignment",
                            },
                        )
                    )

                    continue

            # -------------------------------------------------------------
            # Pattern 4: DEBUG = True
            # -------------------------------------------------------------
            if (
                isinstance(target, ast.Name)
                and target.id == "DEBUG"
            ):
                findings.append(
                    Finding(
                        id="FLASK-CONFIG-001",
                        category="flask",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title="Flask debug configuration is enabled",
                        description=(
                            "A literal DEBUG=True configuration was found. "
                            "Debug mode should not be enabled in production."
                        ),
                        recommendation=(
                            "Disable DEBUG in production and use separate "
                            "development and production configuration."
                        ),
                        file=str(file_path.resolve()),
                        line=node.lineno,
                        metadata={
                            "detection": "debug_constant",
                        },
                    )
                )

    return findings

def _detect_route_conflicts(
    python_files: list[Path],
) -> list[Finding]:
    """
    Detect duplicate Flask routes that resolve to the same path and method.

    This detector intentionally builds on the existing route-discovery logic
    in ``_detect_architecture()`` rather than maintaining a second AST route
    parser. That keeps Blueprint resolution, URL-prefix handling, and HTTP
    method detection consistent across the Flask analyzer.

    A route is considered a duplicate when two discovered routes have the
    same effective URL path and HTTP method.

    Routes using different HTTP methods on the same path are intentionally
    allowed because this is a normal Flask pattern, for example:

        GET  /users
        POST /users

    Malformed Python files are ignored by the architecture discovery layer,
    preserving the analyzer's best-effort behavior.
    """

    findings: list[Finding] = []

    if not python_files:
        return findings

    # ``_detect_architecture`` already knows how to:
    #
    #   - discover @app.route()
    #   - discover @app.get(), @app.post(), etc.
    #   - identify Blueprint routes
    #   - resolve Blueprint registration prefixes
    #   - calculate effective ``full_path`` values
    #
    # Reusing it avoids duplicating all of that logic here.
    architecture = _detect_architecture(python_files)

    routes = architecture.get("routes", [])

    if not isinstance(routes, list):
        return findings

    # Maps (effective_path, HTTP_method) to the first route encountered.
    #
    # We keep the first route so that when a duplicate is found the finding
    # can identify the original endpoint as well as the duplicate endpoint.
    seen_routes: dict[tuple[str, str], dict[str, Any]] = {}

    for route in routes:
        if not isinstance(route, dict):
            continue

        # ``full_path`` is produced by the existing Blueprint-aware route
        # resolution logic. Fall back to ``path`` for routes where no
        # Blueprint registration prefix exists.
        path = route.get("full_path") or route.get("path")

        if not isinstance(path, str) or not path:
            continue

        methods = route.get("methods")

        # Existing route discovery represents methods as a list. Defensive
        # handling here prevents malformed/incomplete metadata from crashing
        # the analyzer.
        if isinstance(methods, str):
            methods = [methods]

        if not isinstance(methods, (list, tuple, set)):
            continue

        endpoint = route.get("endpoint")
        file_value = route.get("file")

        for method in methods:
            if not isinstance(method, str):
                continue

            method = method.upper().strip()

            if not method:
                continue

            route_key = (path, method)

            previous = seen_routes.get(route_key)

            if previous is None:
                seen_routes[route_key] = route
                continue

            # The current route is the duplicate. We report the later route
            # so the finding points directly at the declaration that creates
            # the conflict.
            metadata: dict[str, Any] = {
                "path": path,
                "method": method,
                "conflict_type": "duplicate_route",
                "endpoint": endpoint,
                "previous_endpoint": previous.get("endpoint"),
                "previous_file": previous.get("file"),
                "previous_line": previous.get("line"),
            }

            # Preserve Blueprint information when available. This makes the
            # finding significantly more useful when duplicate routes occur
            # across separate application modules.
            if route.get("blueprint") is not None:
                metadata["blueprint"] = route["blueprint"]

            if previous.get("blueprint") is not None:
                metadata["previous_blueprint"] = previous["blueprint"]

            findings.append(
                Finding(
                    id="FLASK-ROUTE-001",
                    category="flask",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title=f"Duplicate Flask route: {method} {path}",
                    description=(
                        f"The Flask application defines multiple routes "
                        f"for the same HTTP method {method} and path "
                        f"{path!r}. Flask can register both endpoints, "
                        "but the resulting routing behavior may be "
                        "unexpected because one endpoint can effectively "
                        "shadow the other depending on registration order."
                    ),
                    recommendation=(
                        "Remove the duplicate route or give the endpoints "
                        "distinct paths or HTTP methods. If both routes "
                        "are intentional, verify Flask's registration "
                        "order and routing behavior explicitly."
                    ),
                    file=(
                        str(Path(file_value).resolve())
                        if isinstance(file_value, str)
                        else None
                    ),
                    line=route.get("line"),
                    metadata=metadata,
                )
            )

            # Do not replace ``seen_routes`` with the duplicate. Keeping the
            # first declaration means every additional duplicate is compared
            # against the original route and receives consistent metadata.
    return findings