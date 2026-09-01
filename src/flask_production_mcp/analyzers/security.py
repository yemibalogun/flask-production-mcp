
"""AST-based security analyzer for Flask applications."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.base import (
    build_summary,
    calculate_score,
    is_python_file,
)
from flask_production_mcp.analyzers.exclusions import should_exclude_path
from flask_production_mcp.models.findings import (
    AuditResult,
    AuditSummary,
    Confidence,
    Finding,
    Severity,
)

from enum import StrEnum

# ---------------------------------------------------------------------------
# Authentication detection
# ---------------------------------------------------------------------------
#
# These names are intentionally framework-agnostic. The analyzer is looking
# for recognizable authentication signals, not trying to prove that a
# particular authentication implementation is secure.
# ---------------------------------------------------------------------------

AUTH_DECORATOR_NAMES: frozenset[str] = frozenset(
    {
        "login_required",
        "fresh_login_required",
        "jwt_required",
        "jwt_required_optional",
        "auth_required",
        "authentication_required",
        "authenticated",
        "requires_auth",
        "require_auth",
        "requires_login",
        "permission_required",
        "permissions_required",
        "role_required",
        "roles_required",
        "admin_required",
        "staff_required",
    }
)


AUTHENTICATION_FUNCTION_NAMES: frozenset[str] = frozenset(
    {
        "login_required",
        "jwt_required",
        "verify_jwt_in_request",
        "authenticate",
        "authenticate_user",
        "require_auth",
        "check_authentication",
        "check_authenticated",
        "verify_token",
    }
)


AUTHENTICATION_IDENTIFIERS: frozenset[str] = frozenset(
    {
        "current_user",
        "login_manager",
        "jwt",
        "token",
        "access_token",
        "authorization",
        "authenticated",
        "is_authenticated",
        "verify_jwt_in_request",
    }
)

class RouteRisk(StrEnum):
    """Abuse risk classification for application routes."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

HIGH_RISK_ROUTE_PATTERNS: tuple[str, ...] = (
    "/login",
    "/register",
    "/signup",
    "/password",
    "/reset",
    "/forgot",
    "/otp",
    "/verify",
    "/checkout",
    "/payment",
    "/payments",
)


MEDIUM_RISK_ROUTE_PATTERNS: tuple[str, ...] = (
    "/auth",
    "/account",
    "/google",
    "/oauth",
    "/webhook",
)

# ---------------------------------------------------------------------------
# Rate-limit detection
# ---------------------------------------------------------------------------

# Common libraries/frameworks that provide rate limiting for Flask.
#
# This is intentionally broader than Flask-Limiter itself. A production
# application may use a custom wrapper around one of these mechanisms.
RATE_LIMIT_MODULES: frozenset[str] = frozenset(
    {
        "flask_limiter",
        "flask_limiter.util",
        "limits",
        "slowapi",
    }
)

# Function/decorator names commonly associated with custom rate limiting.
#
# These are signals rather than proof. Static analysis cannot determine
# whether the implementation is actually effective at runtime.
RATE_LIMIT_NAMES: frozenset[str] = frozenset(
    {
        "rate_limit",
        "ratelimit",
        "rate_limiter",
        "limiter",
        "limit",
        "throttle",
        "throttler",
        "rate_limited",
        "rate_limit_required",
        "throttle_required",
    }
)

# Names that strongly suggest application-wide request protection.
GLOBAL_RATE_LIMIT_NAMES: frozenset[str] = frozenset(
    {
        "before_request",
        "before_app_request",
        "after_request",
        "before_app_first_request",
    }
)

# ---------------------------------------------------------------------------
# Hardcoded secret detection
# ---------------------------------------------------------------------------

# Configuration names that commonly contain credentials or authentication
# material. We intentionally avoid generic names such as "KEY" or "VALUE"
# because they produce too many false positives.
SECRET_NAME_PATTERNS: tuple[str, ...] = (
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "client_secret",
    "jwt_secret",
    "encryption_key",
    "signing_key",
    "auth_token",
    "access_token",
    "refresh_token",
    "password",
    "passwd",
    "database_url",
    "db_url",
    "dsn",
)

# Values that are clearly placeholders rather than real credentials.
# These should not produce a security finding.
SECRET_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "",
        "changeme",
        "change_me",
        "change-this",
        "change-this-secret",
        "your-secret",
        "your-secret-key",
        "your-api-key",
        "your-api-key-here",
        "your-password",
        "your-password-here",
        "your-token",
        "your-token-here",
        "replace-me",
        "replace_me",
        "replace-this",
        "placeholder",
        "example",
        "test",
        "testing",
        "dummy",
        "dummy-secret",
        "none",
        "null",
    }
)

# Well-known prefixes provide stronger evidence that a string is an actual
# credential. These are useful when the variable name itself is ambiguous.
SECRET_VALUE_PREFIXES: tuple[str, ...] = (
    "sk_live_",
    "sk_test_",
    "sk-",
    "FLWSECK-",
    "FLWPUBK-",
    "whsec_",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "AIza",
)


def _normalize_secret_name(name: str) -> str:
    """Normalize a configuration name for reliable secret matching."""

    return (
        name.strip()
        .lower()
        .replace("-", "_")
    )


def _looks_like_placeholder(value: str) -> bool:
    """Return True when a secret-looking value is obviously a placeholder."""

    normalized = value.strip().lower()

    if normalized in SECRET_PLACEHOLDERS:
        return True

    # Catch common development placeholders such as:
    #     "your-secret-key-here"
    #     "<your-api-key>"
    #     "${SECRET_KEY}"
    placeholder_markers = (
        "your_",
        "your-",
        "<your",
        "<secret",
        "${",
        "{{",
        "replace_",
        "replace-",
        "example_",
        "example-",
    )

    return any(
        marker in normalized
        for marker in placeholder_markers
    )


def _get_imported_module_name(
    node: ast.Import | ast.ImportFrom,
) -> str | None:
    """Return the module name represented by an import statement."""

    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name in RATE_LIMIT_MODULES:
                return alias.name

        return None

    if isinstance(node, ast.ImportFrom):
        if node.module in RATE_LIMIT_MODULES:
            return node.module

    return None


def _is_rate_limit_name(name: str | None) -> bool:
    """Return True when a name strongly resembles rate-limit functionality."""

    if not name:
        return False

    normalized = name.lower().replace("-", "_")

    return (
        normalized in RATE_LIMIT_NAMES
        or "rate_limit" in normalized
        or "ratelimit" in normalized
        or "throttl" in normalized
    )


def _decorator_name(
    decorator: ast.expr,
) -> str | None:
    """
    Extract the final callable name from a decorator.

    Examples:
        @limiter.limit(...)
            -> "limit"

        @rate_limit(...)
            -> "rate_limit"

        @limiter
            -> "limiter"
    """

    target = decorator

    # @something(...)
    if isinstance(target, ast.Call):
        target = target.func

    if isinstance(target, ast.Name):
        return target.id

    if isinstance(target, ast.Attribute):
        return target.attr

    return None


def _is_rate_limit_decorator(
    decorator: ast.expr,
) -> bool:
    """Return True when a decorator appears to apply rate limiting."""

    name = _decorator_name(decorator)

    if _is_rate_limit_name(name):
        return True

    # Handle decorators such as:
    #
    #     @limiter.limit(...)
    #     @limiter.shared_limit(...)
    #     @limiter.exempt
    #
    if isinstance(decorator, ast.Call):
        target = decorator.func

        if isinstance(target, ast.Attribute):
            owner = target.value

            if isinstance(owner, ast.Name):
                owner_name = owner.id.lower()

                if (
                    "limiter" in owner_name
                    or "throttl" in owner_name
                    or "rate" in owner_name
                ):
                    return True

                if "limit" in target.attr.lower():
                    return True

    elif isinstance(decorator, ast.Attribute):
        if "limit" in decorator.attr.lower():
            return True

    return False


def _find_rate_limit_signals(
    file_path: Path,
    tree: ast.AST,
) -> dict[str, Any]:
    """
    Inspect one Python AST for rate-limiting implementation signals.

    The detector deliberately separates strong evidence from weak evidence.

    Strong evidence includes:
        - Flask-Limiter imports
        - Limiter(...) initialization
        - @limiter.limit(...)
        - @limiter.shared_limit(...)
        - recognizable custom rate-limit decorators
        - recognizable rate-limit calls inside request hooks

    Weak evidence includes:
        - generic Flask before_request hooks
        - unrelated functions whose names happen to contain "limit"

    A generic Flask request hook is therefore NOT treated as rate limiting
    unless recognizable rate-limit logic is actually found inside it.
    """

    signals: dict[str, Any] = {
        # --------------------------------------------------------------
        # Library-level evidence.
        # --------------------------------------------------------------
        "library_detected": False,
        "flask_limiter_detected": False,
        "recognized_limiter_library": None,

        # --------------------------------------------------------------
        # Flask-Limiter implementation evidence.
        # --------------------------------------------------------------
        "limiter_initialization_detected": False,
        "limiter_application_detected": False,

        # --------------------------------------------------------------
        # Route-level decorator evidence.
        #
        # This key is required by the project-level analyzer and must
        # remain separate from limiter initialization.
        # --------------------------------------------------------------
        "route_decorator_detected": False,

        # --------------------------------------------------------------
        # Custom implementation evidence.
        # --------------------------------------------------------------
        "custom_rate_limit_detected": False,
        "custom_rate_limit_application_detected": False,

        # --------------------------------------------------------------
        # Global request-hook evidence.
        # --------------------------------------------------------------
        "global_hook_detected": False,
        "global_rate_limit_hook_detected": False,

        # --------------------------------------------------------------
        # Diagnostic locations.
        # --------------------------------------------------------------
        "decorated_routes": [],
        "limiter_initializations": [],
        "global_locations": [],
        "global_rate_limit_locations": [],
        "custom_locations": [],
    }

    # ------------------------------------------------------------------
    # Helper: extract the final callable name from a Call node.
    #
    # Examples:
    #
    #     limiter(...)
    #         -> "limiter"
    #
    #     limiter.limit(...)
    #         -> "limit"
    #
    #     rate_limiter.check(...)
    #         -> "check"
    # ------------------------------------------------------------------
    def get_call_name(call: ast.Call) -> str | None:
        """Return the final callable name represented by a Call node."""

        if isinstance(call.func, ast.Name):
            return call.func.id

        if isinstance(call.func, ast.Attribute):
            return call.func.attr

        return None

    # ------------------------------------------------------------------
    # Helper: determine whether an expression resembles a limiter object.
    #
    # This intentionally does not consider every variable named "limit"
    # to be a limiter. We want to reduce false positives from unrelated
    # application code.
    # ------------------------------------------------------------------
    def looks_like_limiter_owner(expression: ast.expr) -> bool:
        """Return True when an expression resembles a limiter object."""

        if isinstance(expression, ast.Name):
            normalized = expression.id.lower()

            return (
                "limiter" in normalized
                or "throttl" in normalized
                or normalized in {
                    "limit",
                    "ratelimit",
                    "rate_limit",
                }
            )

        if isinstance(expression, ast.Attribute):
            return looks_like_limiter_owner(expression.value)

        return False

    # ------------------------------------------------------------------
    # Walk the complete AST.
    # ------------------------------------------------------------------
    for node in ast.walk(tree):

        # ==============================================================
        # IMPORT DETECTION
        # ==============================================================
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imported_module = _get_imported_module_name(node)

            if imported_module:
                signals["library_detected"] = True

                if imported_module.startswith("flask_limiter"):
                    signals["flask_limiter_detected"] = True
                    signals["recognized_limiter_library"] = (
                        "flask-limiter"
                    )

                elif imported_module == "limits":
                    signals["recognized_limiter_library"] = "limits"

                elif imported_module == "slowapi":
                    signals["recognized_limiter_library"] = "slowapi"

        # ==============================================================
        # CALL DETECTION
        # ==============================================================
        if isinstance(node, ast.Call):
            function_name = get_call_name(node)

            if not function_name:
                continue

            normalized_name = function_name.lower()

            # ----------------------------------------------------------
            # Limiter initialization.
            #
            # Recognizes:
            #
            #     limiter = Limiter(...)
            #
            #     limiter = flask_limiter.Limiter(...)
            #
            #     limiter = RequestLimiter(...)
            #
            # The final case is useful for aliased imports, although AST
            # analysis cannot always prove that the alias really refers
            # to Flask-Limiter.
            # ----------------------------------------------------------
            if (
                normalized_name == "limiter"
                or normalized_name.endswith("limiter")
            ):
                signals["limiter_initialization_detected"] = True

                signals["limiter_initializations"].append(
                    {
                        "line": node.lineno,
                        "function": function_name,
                        "file": str(file_path),
                    }
                )

            # ----------------------------------------------------------
            # Attribute-based limiter usage.
            #
            # Strong examples:
            #
            #     limiter.limit(...)
            #     limiter.shared_limit(...)
            #
            # Custom examples:
            #
            #     rate_limiter.check(...)
            #     limiter.enforce(...)
            #     throttle.consume(...)
            # ----------------------------------------------------------
            if isinstance(node.func, ast.Attribute):
                method_name = node.func.attr.lower()

                # ------------------------------------------------------
                # Flask-Limiter route/application methods.
                # ------------------------------------------------------
                if (
                    method_name in {
                        "limit",
                        "shared_limit",
                    }
                    and looks_like_limiter_owner(node.func.value)
                ):
                    signals["limiter_application_detected"] = True

                # ------------------------------------------------------
                # Recognizable custom limiter APIs.
                # ------------------------------------------------------
                if (
                    method_name
                    in {
                        "check",
                        "check_rate_limit",
                        "enforce",
                        "enforce_limit",
                        "allow",
                        "is_allowed",
                        "consume",
                        "throttle",
                    }
                    and looks_like_limiter_owner(node.func.value)
                ):
                    signals["custom_rate_limit_detected"] = True

                    signals["custom_locations"].append(
                        {
                            "line": node.lineno,
                            "function": method_name,
                            "file": str(file_path),
                        }
                    )

            # ----------------------------------------------------------
            # Direct custom rate-limit calls.
            #
            # These are stronger signals than merely encountering a
            # generic function named "limit".
            # ----------------------------------------------------------
            if normalized_name in {
                "rate_limit",
                "ratelimit",
                "enforce_rate_limit",
                "check_rate_limit",
                "throttle",
                "throttle_request",
                "rate_limit_request",
            }:
                signals["custom_rate_limit_detected"] = True

                signals["custom_locations"].append(
                    {
                        "line": node.lineno,
                        "function": function_name,
                        "file": str(file_path),
                    }
                )

        # ==============================================================
        # FUNCTION / DECORATOR DETECTION
        # ==============================================================
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            for decorator in node.decorator_list:

                # ------------------------------------------------------
                # Rate-limit decorators.
                #
                # Examples:
                #
                #     @limiter.limit("5/minute")
                #     @limiter.shared_limit("10/minute")
                #     @rate_limit(...)
                # ------------------------------------------------------
                if _is_rate_limit_decorator(decorator):
                    decorator_name = _decorator_name(decorator)

                    signals["route_decorator_detected"] = True
                    signals["limiter_application_detected"] = True

                    signals["decorated_routes"].append(
                        {
                            "function": node.name,
                            "line": node.lineno,
                            "decorator": decorator_name,
                            "file": str(file_path),
                        }
                    )

                # ------------------------------------------------------
                # Flask global request hooks.
                #
                # IMPORTANT:
                #
                # Merely seeing @app.before_request is NOT sufficient
                # evidence of rate limiting.
                # ------------------------------------------------------
                target = decorator

                if isinstance(target, ast.Call):
                    target = target.func

                if not isinstance(target, ast.Attribute):
                    continue

                if target.attr not in GLOBAL_RATE_LIMIT_NAMES:
                    continue

                signals["global_hook_detected"] = True

                hook_location: dict[str, Any] = {
                    "function": node.name,
                    "line": node.lineno,
                    "hook": target.attr,
                    "file": str(file_path),
                    "rate_limit_logic_detected": False,
                }

                signals["global_locations"].append(
                    hook_location
                )

                # ------------------------------------------------------
                # Inspect the hook's body.
                #
                # This is what prevents:
                #
                #     @app.before_request
                #     def enforce_session_timeout():
                #         ...
                #
                # from being classified as a rate limiter.
                #
                # We only promote the hook to rate-limit evidence when
                # its body actually calls recognizable rate-limit logic.
                # ------------------------------------------------------
                for child in ast.walk(node):
                    if not isinstance(child, ast.Call):
                        continue

                    call_name = get_call_name(child)

                    if not call_name:
                        continue

                    normalized_call_name = call_name.lower()

                    if normalized_call_name in {
                        "rate_limit",
                        "ratelimit",
                        "enforce_rate_limit",
                        "check_rate_limit",
                        "throttle",
                        "throttle_request",
                        "rate_limit_request",
                    }:
                        hook_location["rate_limit_logic_detected"] = True

                        signals["global_rate_limit_hook_detected"] = True

                        signals["global_rate_limit_locations"].append(
                            hook_location.copy()
                        )

                        signals["custom_rate_limit_detected"] = True

    # ------------------------------------------------------------------
    # A custom implementation becomes stronger evidence when it is
    # actually applied through a recognized decorator or global hook.
    # ------------------------------------------------------------------
    if signals["route_decorator_detected"]:
        signals["custom_rate_limit_application_detected"] = True

    if signals["global_rate_limit_hook_detected"]:
        signals["custom_rate_limit_application_detected"] = True

    return signals

def _classify_route_risk(route: str) -> RouteRisk | None:
    """Classify a route according to likely abuse sensitivity."""

    normalized = route.lower().rstrip("/") or "/"

    if any(
        pattern in normalized
        for pattern in HIGH_RISK_ROUTE_PATTERNS
    ):
        return RouteRisk.HIGH

    if any(
        pattern in normalized
        for pattern in MEDIUM_RISK_ROUTE_PATTERNS
    ):
        return RouteRisk.MEDIUM

    return None


# URL/path keywords that commonly identify endpoints requiring
# stronger abuse protection. This is intentionally conservative;
# the analyzer will still report these findings with medium confidence.
SENSITIVE_ROUTE_PATTERNS: tuple[str, ...] = (
    "/login",
    "/register",
    "/signup",
    "/auth",
    "/password",
    "/reset",
    "/forgot",
    "/otp",
    "/verify",
    "/account",
    "/checkout",
    "/payment",
    "/payments",
    "/webhook",
)


def _extract_route_path(
    decorator: ast.expr,
) -> str | None:
    """
    Extract a statically defined Flask route from a decorator.

    Supported patterns include:

        @app.route("/login")
        @app.post("/login")
        @bp.route("/login")
        @auth_bp.post("/login")
        @app.route(rule="/login")

    Dynamic routes such as:

        @app.route(SOME_VARIABLE)

    are intentionally ignored because static analysis cannot safely
    determine their actual URL.
    """

    if not isinstance(decorator, ast.Call):
        return None

    function = decorator.func

    # Flask route decorators are normally attribute calls:
    #
    #     app.route(...)
    #     app.post(...)
    #     blueprint.route(...)
    #
    if not isinstance(function, ast.Attribute):
        return None

    if function.attr not in {
        "route",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
    }:
        return None

    # Handle:
    #
    #     @app.route("/login")
    #
    # and:
    #
    #     @app.post("/login")
    if decorator.args:
        first_argument = decorator.args[0]

        if isinstance(first_argument, ast.Constant):
            if isinstance(first_argument.value, str):
                return first_argument.value

    # Handle:
    #
    #     @app.route(rule="/login")
    for keyword in decorator.keywords:
        if keyword.arg != "rule":
            continue

        if isinstance(keyword.value, ast.Constant):
            if isinstance(keyword.value.value, str):
                return keyword.value.value

    return None


def _finding_for_dangerous_call(
    *,
    function_name: str,
    file_path: Path,
    line: int,
) -> Finding:
    """Create a finding for a dangerous Python function."""

    if function_name == "eval":
        return Finding(
            id="SEC-CODE-001",
            category="security",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            title="Potential unsafe eval() usage",
            description=(
                f"The function eval() is used in {file_path.name} "
                f"at line {line}. Static analysis cannot determine "
                "whether the evaluated expression is influenced by "
                "untrusted input."
            ),
            recommendation=(
                "Avoid eval() whenever possible. Replace dynamic "
                "evaluation with explicit parsing, a dispatch table, "
                "or another constrained implementation."
            ),
            file=str(file_path),
            line=line,
            metadata={
                "function": "eval",
                "requires_data_flow_review": True,
            },
        )

    return Finding(
        id="SEC-CODE-002",
        category="security",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        title="Potential unsafe exec() usage",
        description=(
            f"The function exec() is used in {file_path.name} "
            f"at line {line}. Dynamic execution of Python source "
            "can result in arbitrary code execution when untrusted "
            "input reaches the call."
        ),
        recommendation=(
            "Remove exec() where possible. Replace dynamic execution "
            "with explicit application logic or a restricted parser."
        ),
        file=str(file_path),
        line=line,
        metadata={
            "function": "exec",
            "requires_data_flow_review": True,
        },
    )


def _find_dangerous_calls(
    file_path: Path,
    tree: ast.AST,
) -> list[Finding]:
    """Find direct eval() and exec() calls in an AST."""

    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        function_name: str | None = None

        # Detect:
        #
        #     eval(...)
        #     exec(...)
        if isinstance(node.func, ast.Name):
            if node.func.id in {"eval", "exec"}:
                function_name = node.func.id

        # Detect:
        #
        #     builtins.eval(...)
        #     builtins.exec(...)
        elif isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "builtins"
                and node.func.attr in {"eval", "exec"}
            ):
                function_name = node.func.attr

        if function_name is None:
            continue

        findings.append(
            _finding_for_dangerous_call(
                function_name=function_name,
                file_path=file_path,
                line=node.lineno,
            )
        )

    return findings


def _find_pickle_deserialization(
    file_path: Path,
    tree: ast.AST,
) -> list[Finding]:
    """Detect potentially unsafe pickle deserialization."""

    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not isinstance(node.func, ast.Attribute):
            continue

        if node.func.attr not in {"load", "loads"}:
            continue

        # Only flag an explicitly referenced pickle object.
        #
        # This prevents false positives for unrelated calls such as:
        #
        #     json.loads(...)
        #     response.loads(...)
        if not (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pickle"
        ):
            continue

        findings.append(
            Finding(
                id="SEC-CODE-003",
                category="security",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title="Unsafe pickle deserialization detected",
                description=(
                    f"pickle.{node.func.attr}() is used in "
                    f"{file_path.name}. Python pickle data can execute "
                    "arbitrary code during deserialization."
                ),
                recommendation=(
                    "Do not deserialize untrusted pickle data. "
                    "Use a safe serialization format such as JSON "
                    "where appropriate."
                ),
                file=str(file_path),
                line=node.lineno,
                metadata={
                    "function": f"pickle.{node.func.attr}",
                    "requires_data_flow_review": True,
                },
            )
        )

    return findings


def _find_hardcoded_secrets(
    file_path: Path,
    tree: ast.AST,
) -> list[Finding]:
    """
    Detect potentially hardcoded secrets in Python source.

    The detector intentionally distinguishes between:

    - Environment-backed secrets:
          SECRET_KEY = os.getenv("SECRET_KEY")
          SECRET_KEY = os.environ.get("SECRET_KEY")

    - Empty configuration values:
          SECRET_KEY = ""

    - Obvious placeholders/test credentials:
          SECRET_KEY = "your-secret-key-here"
          SECRET_KEY = "change-me"
          FLUTTERWAVE_SECRET_KEY = "test_secret_key"

    - Actual literal credentials:
          SECRET_KEY = "real-production-secret-123456"

    Static analysis cannot prove that a string is truly secret. The goal is
    therefore to detect high-confidence hardcoded credentials while avoiding
    common development/test configuration false positives.
    """

    findings: list[Finding] = []

    # ------------------------------------------------------------------
    # Values that are clearly not production credentials.
    #
    # These are intentionally normalized to lowercase before comparison.
    # Exact matching prevents us from accidentally suppressing a real
    # credential merely because it contains a word such as "test".
    # ------------------------------------------------------------------
    SAFE_LITERAL_VALUES: frozenset[str] = frozenset(
        {
            "",
            "test",
            "testing",
            "test_key",
            "test_secret",
            "test_secret_key",
            "test_secret_hash",
            "test_public_key",
            "dummy",
            "dummy_key",
            "dummy_secret",
            "dummy_secret_key",
            "placeholder",
            "placeholder_key",
            "placeholder_secret",
            "your-secret-key",
            "your_secret_key",
            "your-secret-key-here",
            "your_secret_key_here",
            "change-me",
            "change_me",
            "changeme",
            "replace-me",
            "replace_me",
            "replace-this",
            "replace_this",
            "example",
            "example_key",
            "example_secret",
            "example_secret_key",
            "example-secret",
            "example-secret-key",
        }
    )

    # ------------------------------------------------------------------
    # Words that strongly indicate a development/test configuration.
    #
    # We use these only as supporting evidence. Merely containing "test"
    # does not automatically make a value safe because a real secret
    # could legitimately contain that substring.
    # ------------------------------------------------------------------
    SAFE_CONTEXT_MARKERS: frozenset[str] = frozenset(
        {
            "test",
            "testing",
            "pytest",
            "unittest",
            "fixture",
            "dummy",
            "mock",
            "example",
            "placeholder",
        }
    )

    def _is_environment_lookup(value: ast.expr) -> bool:
        """
        Determine whether an assignment value comes from the environment.

        Supported examples:

            os.getenv("SECRET_KEY")
            os.environ.get("SECRET_KEY")
            os.environ["SECRET_KEY"]
            environ.get("SECRET_KEY")

        This is intentionally AST-based rather than text-based so that
        formatting and whitespace do not affect detection.
        """

        # os.getenv(...)
        if isinstance(value, ast.Call):
            function = value.func

            if (
                isinstance(function, ast.Attribute)
                and function.attr in {"getenv", "get"}
                and isinstance(function.value, ast.Attribute)
                and isinstance(function.value.value, ast.Name)
                and function.value.value.id == "os"
                and function.value.attr == "environ"
            ):
                return True

            # os.getenv(...)
            if (
                isinstance(function, ast.Attribute)
                and function.attr == "getenv"
                and isinstance(function.value, ast.Name)
                and function.value.id == "os"
            ):
                return True

            # environ.get(...)
            if (
                isinstance(function, ast.Attribute)
                and function.attr == "get"
                and isinstance(function.value, ast.Name)
                and function.value.id in {"environ", "ENV"}
            ):
                return True

        # os.environ["SECRET_KEY"]
        if isinstance(value, ast.Subscript):
            target = value.value

            if (
                isinstance(target, ast.Attribute)
                and target.attr == "environ"
                and isinstance(target.value, ast.Name)
                and target.value.id == "os"
            ):
                return True

            # environ["SECRET_KEY"]
            if (
                isinstance(target, ast.Name)
                and target.id in {"environ", "ENV"}
            ):
                return True

        return False

    def _literal_string(value: ast.expr) -> str | None:
        """
        Extract a literal string value.

        Non-literal expressions intentionally return None because they
        require data-flow analysis rather than simple AST inspection.
        """

        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value

        return None

    def _looks_like_safe_test_or_placeholder(
        variable_name: str,
        value: str,
    ) -> bool:
        """
        Determine whether a literal is an obvious test/placeholder value.

        The variable name is considered together with the literal so that
        values such as "test_secret_key" are recognized without treating
        every string containing the word "test" as safe.
        """

        normalized_value = value.strip().lower()
        normalized_variable = variable_name.lower()

        # Exact known placeholders/test credentials are always safe.
        if normalized_value in SAFE_LITERAL_VALUES:
            return True

        # Very short values are generally not useful production secrets.
        # We only suppress them when they also contain an explicit
        # development/test marker.
        if len(normalized_value) < 12:
            return any(
                marker in normalized_value
                for marker in SAFE_CONTEXT_MARKERS
            )

        # Development-style values such as:
        #
        #     test_secret_key_123
        #     pytest-secret-value
        #     dummy-flutterwave-secret
        #
        # require both a development marker and a secret-like variable
        # name before being treated as safe.
        has_context_marker = any(
            marker in normalized_value
            for marker in SAFE_CONTEXT_MARKERS
        )

        has_secret_variable_name = any(
            keyword in normalized_variable
            for keyword in (
                "secret",
                "password",
                "token",
                "credential",
                "api_key",
                "apikey",
                "private_key",
            )
        )

        return has_context_marker and has_secret_variable_name

    def _target_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
        """Extract variable names from assignment targets."""

        names: list[str] = []

        targets: list[ast.expr]

        if isinstance(node, ast.Assign):
            targets = node.targets
        else:
            targets = [node.target]

        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)

        return names

    # ------------------------------------------------------------------
    # Secret-like variable names.
    #
    # Keep this deliberately focused on credentials rather than generic
    # configuration variables such as DEBUG or DATABASE_URL.
    # ------------------------------------------------------------------
    secret_name_patterns: tuple[str, ...] = (
        "secret",
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "access_key",
        "auth_key",
        "credential",
    )

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue

        variable_names = _target_names(node)

        if not variable_names:
            continue

        value_node = (
            node.value
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            else None
        )

        if value_node is None:
            continue

        for variable_name in variable_names:
            normalized_name = variable_name.lower()

            # Only inspect variables whose names strongly suggest that
            # they contain credentials.
            if not any(
                pattern in normalized_name
                for pattern in secret_name_patterns
            ):
                continue

            # ----------------------------------------------------------
            # Environment-backed configuration is not hardcoded.
            # ----------------------------------------------------------
            if _is_environment_lookup(value_node):
                continue

            # ----------------------------------------------------------
            # Only literal strings can be classified confidently here.
            #
            # Expressions such as:
            #
            #     SECRET_KEY = generate_secret()
            #
            # require data-flow/runtime analysis and are intentionally
            # not reported by this detector.
            # ----------------------------------------------------------
            literal_value = _literal_string(value_node)

            if literal_value is None:
                continue

            # ----------------------------------------------------------
            # Ignore obvious development/test/placeholder values.
            # ----------------------------------------------------------
            if _looks_like_safe_test_or_placeholder(
                variable_name,
                literal_value,
            ):
                continue

            findings.append(
                Finding(
                    id="SEC-CONFIG-003",
                    category="security",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    title="Potential hardcoded secret detected",
                    description=(
                        f"The variable {variable_name!r} in "
                        f"{file_path.name} at line {node.lineno} "
                        "contains a hardcoded secret-like value. "
                        "Credentials embedded in source code can be "
                        "committed to version control, exposed in build "
                        "artifacts, or leaked through source distribution."
                    ),
                    recommendation=(
                        "Remove the credential from source code and load "
                        "it from environment variables or a dedicated "
                        "secret-management system. Rotate the credential "
                        "if it has already been exposed or committed to "
                        "version control."
                    ),
                    file=str(file_path),
                    line=node.lineno,
                    metadata={
                        "variable": variable_name,
                        "value_exposed": False,
                        "requires_rotation_review": True,
                    },
                )
            )

    return findings



def analyze_python_file(
    file_path: Path,
) -> list[Finding]:
    """
    Analyze one Python source file.

    File-level checks include:
    - dangerous dynamic execution
    - unsafe pickle deserialization
    - Flask debug configuration
    - hardcoded credentials

    Project-wide checks such as determining whether rate limiting exists
    elsewhere in the application belong to ``analyze_security()``.
    """

    try:
        source = file_path.read_text(
            encoding="utf-8-sig",
            errors="replace",
        )
    except OSError:
        # An unreadable file should not terminate the complete audit.
        return []

    try:
        tree = ast.parse(
            source,
            filename=str(file_path),
        )
    except SyntaxError:
        # Syntax errors are handled by a future code-quality analyzer.
        # Security analysis skips invalid Python safely.
        return []

    findings: list[Finding] = []

    findings.extend(
        _find_dangerous_calls(
            file_path,
            tree,
        )
    )

    findings.extend(
        _find_pickle_deserialization(
            file_path,
            tree,
        )
    )

    findings.extend(
        _find_debug_configuration(
            file_path,
            tree,
        )
    )

    findings.extend(
        _find_hardcoded_secrets(
            file_path,
            tree,
        )
    )


    # Rate-limit analysis remains project-level. A limiter can be initialized
    # in extensions.py and consumed from routes.py, so checking it here would
    # create false positives.
    return findings


def analyze_security(
    project_root: Path,
) -> AuditResult:
    """
    Run the complete security analyzer against a Flask project.

    Security analysis is performed in two layers:

    1. File-level AST analysis:
       - eval()
       - exec()
       - pickle deserialization
       - debug configuration
       - sensitive route protection

    2. Project-level analysis:
       - Flask-Limiter
       - recognized limiter initialization
       - custom rate limiting
       - global request hooks
       - absence of recognizable rate limiting

    Keeping these layers separate prevents a route-level check from
    incorrectly concluding that the entire project has no rate limiter.
    """

    project = Path(project_root).expanduser().resolve()

    if not project.exists():
        return AuditResult(
            success=False,
            project_path=str(project),
            score=0,
            findings=[],
            summary=AuditSummary(),
            recommendations=[],
            errors=[
                f"Project path does not exist: {project}",
            ],
        )

    if not project.is_dir():
        return AuditResult(
            success=False,
            project_path=str(project),
            score=0,
            findings=[],
            summary=AuditSummary(),
            recommendations=[],
            errors=[
                f"Project path is not a directory: {project}",
            ],
        )

    findings: list[Finding] = []
    errors: list[str] = []

    try:
        python_files = project.rglob("*.py")

        for file_path in python_files:
            if not is_python_file(file_path):
                continue

            if should_exclude_path(
                file_path,
                project,
            ):
                continue

            try:
                findings.extend(
                    analyze_python_file(file_path)
                )
            except Exception as exc:
                # A failure in one analyzer/file must not prevent the
                # remainder of the project from being audited.
                errors.append(
                    f"Failed to analyze {file_path}: {exc}"
                )

        # ---------------------------------------------------------------
        # Project-level authentication detection
        # ---------------------------------------------------------------
        #
        # Authentication can be defined in a completely different module
        # from the route. Therefore SEC-AUTH-005 must be evaluated only
        # after the entire project has been inspected.
        # ---------------------------------------------------------------
        try:
            authentication_signals = _analyze_project_authentication(
                project
            )

            findings.extend(
                _analyze_project_authentication_routes(
                    project,
                    authentication_signals,
                )
            )

        except Exception as exc:
            errors.append(
                f"Authentication project analysis failed: {exc}"
            )
        # ---------------------------------------------------------------
        # Project-level rate-limit detection
        # ---------------------------------------------------------------
        #
        # This must happen AFTER scanning the project because the limiter
        # may be initialized in extensions.py while routes live in several
        # separate blueprint modules.
        #
        # Most importantly, SEC-AUTH-002 is generated only here. It should
        # NOT be independently generated by every route file.
        # ---------------------------------------------------------------
        try:
            findings.extend(
                _analyze_project_rate_limiting(project)
            )
        except Exception as exc:
            errors.append(
                f"Rate-limit project analysis failed: {exc}"
            )

    except OSError as exc:
        errors.append(
            f"Unable to enumerate project files: {exc}"
        )

    summary = build_summary(findings)
    score = calculate_score(findings)

    # Preserve recommendation order while removing duplicates.
    recommendations = list(
        dict.fromkeys(
            finding.recommendation
            for finding in findings
            if finding.recommendation
        )
    )

    return AuditResult(
        success=True,
        project_path=str(project),
        score=score,
        findings=findings,
        summary=summary,
        recommendations=recommendations,
        errors=errors,
    )

def _find_debug_configuration(
    file_path: Path,
    tree: ast.AST,
) -> list[Finding]:
    """
    Detect explicitly enabled Flask debug configuration.

    The analyzer distinguishes between environment-specific configuration
    classes so that intentional DEBUG=True settings in development and
    testing configurations are not incorrectly reported as production
    vulnerabilities.

    Findings:
        SEC-DEBUG-001:
            Explicit ``app.run(debug=True)``.

        SEC-DEBUG-002:
            Explicit ``DEBUG = True`` in a production/general configuration.

    DevelopmentConfig and TestingConfig are intentionally excluded because
    Flask debug mode is expected in those environments.
    """

    findings: list[Finding] = []

    # ------------------------------------------------------------------
    # Detect ``app.run(debug=True)``
    # ------------------------------------------------------------------
    #
    # This is still security-relevant because accidentally deploying the
    # development entry point can expose the Werkzeug debugger.
    #
    # However, run.py is commonly a local-development entry point. We
    # therefore assign a lower severity when the filename strongly indicates
    # that it is a development launcher.
    #
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not isinstance(node.func, ast.Attribute):
            continue

        if node.func.attr != "run":
            continue

        for keyword in node.keywords:
            if keyword.arg != "debug":
                continue

            if not (
                isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                continue

            # ``run.py`` is conventionally a local development launcher.
            # A different file containing app.run(debug=True) is more
            # suspicious because it may represent an application entry point
            # that could accidentally be deployed.
            is_development_launcher = file_path.name.lower() in {
                "run.py",
                "dev.py",
                "development.py",
            }

            severity = (
                Severity.MEDIUM
                if is_development_launcher
                else Severity.CRITICAL
            )

            confidence = Confidence.HIGH

            findings.append(
                Finding(
                    id="SEC-DEBUG-001",
                    category="security",
                    severity=severity,
                    confidence=confidence,
                    title="Flask debug mode explicitly enabled",
                    description=(
                        f"Flask debug mode is explicitly enabled "
                        f"in {file_path.name} at line {node.lineno}. "
                        "The Werkzeug debugger must never be exposed "
                        "to production traffic."
                    ),
                    recommendation=(
                        "Keep debug mode restricted to local development "
                        "and ensure production is started through a "
                        "production WSGI server such as Gunicorn."
                    ),
                    file=str(file_path),
                    line=node.lineno,
                    metadata={
                        "pattern": "app.run(debug=True)",
                        "development_launcher": is_development_launcher,
                    },
                )
            )

    # ------------------------------------------------------------------
    # Detect ``DEBUG = True``
    # ------------------------------------------------------------------
    #
    # We need to know which configuration class contains the assignment.
    #
    # Examples:
    #
    #     class DevelopmentConfig(BaseConfig):
    #         DEBUG = True
    #
    #     class TestingConfig(BaseConfig):
    #         DEBUG = True
    #
    # These are intentional and should NOT produce production findings.
    #
    # Conversely:
    #
    #     class ProductionConfig(BaseConfig):
    #         DEBUG = True
    #
    # is a genuine critical finding.
    #
    # A module-level:
    #
    #     DEBUG = True
    #
    # is treated as high severity because we cannot safely determine which
    # environment will consume the configuration.
    #

    # Track the current class while walking the module body. ``ast.walk``
    # does not preserve enough parent context to reliably determine which
    # class contains an assignment, so we inspect class bodies explicitly.
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue

        class_name = node.name.lower()

        # These configuration classes are explicitly non-production.
        is_non_production_config = class_name in {
            "developmentconfig",
            "testingconfig",
            "testconfig",
            "devconfig",
        }

        # These names explicitly identify production configuration.
        is_production_config = (
            "production" in class_name
            or class_name in {
                "prodconfig",
                "prod",
            }
        )

        for child in node.body:
            if not isinstance(child, ast.Assign):
                continue

            is_debug_assignment = any(
                isinstance(target, ast.Name)
                and target.id.upper() == "DEBUG"
                for target in child.targets
            )

            if not is_debug_assignment:
                continue

            # Only flag an explicitly literal ``True``.
            #
            # Dynamic configuration such as:
            #
            #     DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
            #
            # cannot be safely evaluated by static analysis and therefore
            # should not be reported as an explicit DEBUG=True assignment.
            if not (
                isinstance(child.value, ast.Constant)
                and child.value.value is True
            ):
                continue

            # DEBUG=True is expected in development and test configurations.
            if is_non_production_config:
                continue

            severity = (
                Severity.CRITICAL
                if is_production_config
                else Severity.HIGH
            )

            findings.append(
                Finding(
                    id="SEC-DEBUG-002",
                    category="security",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    title="Flask DEBUG configuration explicitly enabled",
                    description=(
                        f"DEBUG=True is explicitly configured in "
                        f"{file_path.name} inside {node.name} at line "
                        f"{child.lineno}. Debug mode can expose sensitive "
                        "application internals and the interactive "
                        "Werkzeug debugger."
                    ),
                    recommendation=(
                        "Set DEBUG=False in production. Development and "
                        "testing configurations may enable debug mode, but "
                        "the production configuration must explicitly "
                        "disable it or load it from a controlled environment "
                        "variable."
                    ),
                    file=str(file_path),
                    line=child.lineno,
                    metadata={
                        "pattern": "DEBUG=True",
                        "config_class": node.name,
                        "production_config": is_production_config,
                        "non_production_config": is_non_production_config,
                    },
                )
            )

    # ------------------------------------------------------------------
    # Detect module-level ``DEBUG = True``
    # ------------------------------------------------------------------
    #
    # Class-contained assignments were handled above. We separately inspect
    # only the module body so we do not duplicate findings from nested
    # configuration classes.
    #
    if isinstance(tree, ast.Module):
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue

            is_debug_assignment = any(
                isinstance(target, ast.Name)
                and target.id.upper() == "DEBUG"
                for target in node.targets
            )

            if not is_debug_assignment:
                continue

            if not (
                isinstance(node.value, ast.Constant)
                and node.value.value is True
            ):
                continue

            findings.append(
                Finding(
                    id="SEC-DEBUG-002",
                    category="security",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title="Flask DEBUG configuration explicitly enabled",
                    description=(
                        f"DEBUG=True is explicitly configured at module level "
                        f"in {file_path.name} at line {node.lineno}. Debug mode "
                        "can expose sensitive application internals and the "
                        "interactive Werkzeug debugger."
                    ),
                    recommendation=(
                        "Remove the module-level DEBUG=True setting and use "
                        "environment-specific configuration. Production "
                        "configuration should explicitly disable debug mode."
                    ),
                    file=str(file_path),
                    line=node.lineno,
                    metadata={
                        "pattern": "DEBUG=True",
                        "config_class": None,
                        "production_config": False,
                        "non_production_config": False,
                    },
                )
            )

    return findings


def _find_rate_limit_configuration(
    tree: ast.AST,
) -> bool:
    """
    Detect recognizable Flask rate-limiting implementation signals.

    Returns:
        True when the application appears to have rate-limiting support.
    """

    flask_limiter_imported = False
    limiter_instance_found = False
    limiter_decorator_found = False
    rate_limit_config_found = False

    for node in ast.walk(tree):
        # Detect:
        #     from flask_limiter import Limiter
        #     import flask_limiter
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "flask_limiter":
                    flask_limiter_imported = True

        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("flask_limiter"):
                flask_limiter_imported = True

        # Detect:
        #     limiter = Limiter(...)
        #     limiter = flask_limiter.Limiter(...)
        elif isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Call):
                call = node.value

                if isinstance(call.func, ast.Name):
                    if call.func.id == "Limiter":
                        limiter_instance_found = True

                elif isinstance(call.func, ast.Attribute):
                    if call.func.attr == "Limiter":
                        limiter_instance_found = True

            # Detect configuration such as:
            #     RATELIMIT_ENABLED = True
            #     RATELIMIT_DEFAULT = "200/day"
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id.upper().startswith("RATELIMIT_")
                ):
                    rate_limit_config_found = True

        # Detect:
        #     @limiter.limit(...)
        #     @limiter.shared_limit(...)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue

                if not isinstance(decorator.func, ast.Attribute):
                    continue

                if decorator.func.attr in {
                    "limit",
                    "shared_limit",
                }:
                    limiter_decorator_found = True

    return (
        flask_limiter_imported
        or limiter_instance_found
        or limiter_decorator_found
        or rate_limit_config_found
    )


def _has_authentication_decorator(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """
    Determine whether a route has a recognizable authentication decorator.

    The detector intentionally supports common decorator names rather than
    tying the analyzer to one authentication framework.
    """

    for decorator in function_node.decorator_list:
        name = _decorator_name(decorator)

        if not name:
            continue

        # A decorator may be represented as:
        #
        #     @login_required
        #     @auth.login_required
        #     @jwt_required()
        #
        # We therefore inspect only the final component.
        base_name = name.split(".")[-1].lower()

        if base_name in AUTH_DECORATOR_NAMES:
            return True

    return False

AUTHENTICATION_ROUTE_PATTERNS: tuple[str, ...] = (
    "/account",
    "/admin",
    "/dashboard",
    "/profile",
    "/settings",
    "/user",
    "/users",
    "/me",
    "/checkout",
    "/payment",
    "/payments",
    "/order",
    "/orders",
    "/private",
)


def _is_sensitive_auth_route(route: str) -> bool:
    """Return True when a route commonly requires authentication."""

    normalized = route.lower().rstrip("/") or "/"

    return any(
        pattern in normalized
        for pattern in AUTHENTICATION_ROUTE_PATTERNS
    )

def _has_rate_limit_decorator(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[bool, str | None]:
    """
    Determine whether a route has an explicit rate-limit decorator.

    Uses the same centralized decorator detection logic as the
    project-level analyzer so route-level and project-level detection
    cannot disagree about what constitutes a rate-limit decorator.
    """

    for decorator in function_node.decorator_list:
        if not _is_rate_limit_decorator(decorator):
            continue

        return True, _decorator_name(decorator)

    return False, None


def _is_rate_limit_exempt(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """Return True when a route is explicitly exempt from rate limiting."""

    for decorator in function_node.decorator_list:
        name = _decorator_name(decorator)

        if not name:
            continue

        if name.split(".")[-1] in {
            "exempt",
            "rate_limit_exempt",
        }:
            return True

    return False


def _analyze_project_rate_limiting(
    project_root: Path,
) -> list[Finding]:
    """
    Analyze rate-limiting coverage across the entire Flask project.

    Rate-limit detection is project-wide because the implementation may be
    split across multiple modules:

        app/extensions.py
            limiter = Limiter(...)

        app/auth/routes.py
            @limiter.limit("5/minute")

    The detector distinguishes between:

        1. Flask-Limiter / recognized limiter library
        2. Custom rate limiting
        3. Global hooks that actually contain rate-limit logic
        4. Global hooks unrelated to rate limiting
        5. No recognizable rate limiting

    A generic Flask ``before_request`` hook is deliberately NOT considered
    evidence of rate limiting.
    """

    project_signals: dict[str, Any] = {
        "library_detected": False,
        "flask_limiter_detected": False,
        "recognized_limiter_library": None,

        "limiter_initialization_detected": False,
        "limiter_application_detected": False,

        "custom_rate_limit_detected": False,
        "custom_rate_limit_application_detected": False,

        "global_hook_detected": False,
        "global_rate_limit_hook_detected": False,

        "decorated_routes": [],
        "limiter_initializations": [],
        "global_locations": [],
        "global_rate_limit_locations": [],
        "custom_locations": [],
    }

    try:
        python_files = list(project_root.rglob("*.py"))
    except OSError:
        # If enumeration fails, do not manufacture a vulnerability finding.
        return []

    for file_path in python_files:
        if not is_python_file(file_path):
            continue

        if should_exclude_path(file_path, project_root):
            continue

        try:
            source = file_path.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )

            tree = ast.parse(
                source,
                filename=str(file_path),
            )

        except (OSError, SyntaxError):
            # One bad source file must not invalidate the entire project
            # security audit.
            continue

        signals = _find_rate_limit_signals(
            file_path,
            tree,
        )

        # --------------------------------------------------------------
        # Merge boolean signals.
        # --------------------------------------------------------------
        for key in (
            "library_detected",
            "flask_limiter_detected",
            "limiter_initialization_detected",
            "limiter_application_detected",
            "custom_rate_limit_detected",
            "custom_rate_limit_application_detected",
            "global_hook_detected",
            "global_rate_limit_hook_detected",
        ):
            project_signals[key] = (
                project_signals[key] or signals[key]
            )

        # --------------------------------------------------------------
        # Preserve the first recognized limiter library.
        # --------------------------------------------------------------
        if (
            project_signals["recognized_limiter_library"] is None
            and signals["recognized_limiter_library"] is not None
        ):
            project_signals["recognized_limiter_library"] = (
                signals["recognized_limiter_library"]
            )

        # --------------------------------------------------------------
        # Merge diagnostic locations.
        # --------------------------------------------------------------
        for key in (
            "decorated_routes",
            "limiter_initializations",
            "global_locations",
            "global_rate_limit_locations",
            "custom_locations",
        ):
            project_signals[key].extend(
                signals[key]
            )

    # ==================================================================
    # CASE 1: Flask-Limiter or another recognized limiter library has
    # actually been initialized.
    #
    # Importing the library alone is insufficient.
    # ==================================================================
    if (
        project_signals["flask_limiter_detected"]
        and project_signals["limiter_initialization_detected"]
    ):
        return []

    # ==================================================================
    # CASE 2: A recognizable limiter has been initialized even if the
    # import was indirect or aliased.
    #
    # Example:
    #
    #     from flask_limiter import Limiter as RequestLimiter
    #     limiter = RequestLimiter(...)
    #
    # The AST cannot always resolve aliases perfectly, so initialization
    # plus route application is accepted as strong evidence.
    # ==================================================================
    if (
        project_signals["limiter_initialization_detected"]
        and project_signals["limiter_application_detected"]
    ):
        return []

    # ==================================================================
    # CASE 3: A custom rate limiter is actually being applied.
    # ==================================================================
    if project_signals["custom_rate_limit_application_detected"]:
        return []

    # ==================================================================
    # CASE 4: A custom rate limiter is detected, but static analysis
    # cannot establish that it is actually applied.
    #
    # This should NOT be treated as "no rate limiting". Instead, give
    # developers a low-confidence manual-review finding.
    # ==================================================================
    if project_signals["custom_rate_limit_detected"]:
        location = (
            project_signals["custom_locations"][0]
            if project_signals["custom_locations"]
            else {}
        )

        return [
            Finding(
                id="SEC-AUTH-004",
                category="security",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                title="Custom rate-limiting logic detected",
                description=(
                    "The project contains code that appears to implement "
                    "rate limiting or request throttling, but static "
                    "analysis could not establish that the mechanism is "
                    "consistently applied to abuse-sensitive routes."
                ),
                recommendation=(
                    "Review the detected custom rate-limiting implementation "
                    "and verify that it enforces effective per-client or "
                    "per-identity limits on authentication, OTP, password "
                    "reset, account recovery, payment, checkout, and other "
                    "abuse-sensitive endpoints."
                ),
                file=location.get("file"),
                line=location.get("line"),
                metadata={
                    "project_level_check": True,
                    "custom_rate_limit": True,
                    "requires_manual_review": True,
                    "custom_locations": (
                        project_signals["custom_locations"]
                    ),
                },
            )
        ]

    # ==================================================================
    # CASE 5: A global request hook exists and explicitly invokes
    # recognizable rate-limit logic.
    #
    # This is stronger than a generic before_request hook.
    # ==================================================================
    if project_signals["global_rate_limit_hook_detected"]:
        location = (
            project_signals["global_rate_limit_locations"][0]
            if project_signals["global_rate_limit_locations"]
            else {}
        )

        return []

    # ==================================================================
    # CASE 6: Generic global hooks exist, but none contain recognizable
    # rate-limit logic.
    #
    # IMPORTANT:
    #
    # This is NOT reported as rate limiting.
    #
    # For example:
    #
    #     @app.before_request
    #     def enforce_session_timeout():
    #         ...
    #
    # is unrelated to request-rate limiting.
    # ==================================================================
    if project_signals["global_hook_detected"]:
        location = (
            project_signals["global_locations"][0]
            if project_signals["global_locations"]
            else {}
        )

        return [
            Finding(
                id="SEC-AUTH-004",
                category="security",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                title="Global request hook requires rate-limit review",
                description=(
                    "A Flask global request hook was detected, but static "
                    "analysis found no recognizable rate-limiting logic "
                    "inside the hook. The hook is therefore not considered "
                    "rate limiting automatically."
                ),
                recommendation=(
                    "Verify independently that application-wide rate "
                    "limiting is enforced through Flask-Limiter, custom "
                    "middleware, an API gateway, reverse proxy, or another "
                    "request-control mechanism."
                ),
                file=location.get("file"),
                line=location.get("line"),
                metadata={
                    "project_level_check": True,
                    "requires_manual_review": True,
                    "rate_limit_logic_detected": False,
                    "global_hooks": project_signals["global_locations"],
                },
            )
        ]

    # ==================================================================
    # CASE 7: Nothing recognizable was found.
    # ==================================================================
    return [
        Finding(
            id="SEC-AUTH-002",
            category="security",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            title="Rate limiting was not detected",
            description=(
                "No recognizable application-level rate-limiting "
                "implementation was detected in the project. "
                "Authentication, OTP, password reset, account recovery, "
                "payment, checkout, and other abuse-sensitive endpoints "
                "may be vulnerable to automated requests."
            ),
            recommendation=(
                "Implement rate limiting for authentication, OTP, "
                "password reset, account recovery, payment, checkout, "
                "and other abuse-sensitive endpoints. Flask-Limiter "
                "or an equivalent distributed rate-limiting solution "
                "can be used."
            ),
            file=None,
            line=None,
            metadata={
                "project_level_check": True,
                "requires_route_review": True,
                "rate_limit_detected": False,
                "flask_limiter_detected": False,
                "custom_rate_limit_detected": False,
            },
        )
    ]


def _contains_authentication_signal(
    node: ast.AST,
) -> bool:
    """
    Determine whether an AST node contains recognizable authentication logic.

    This is deliberately conservative. We are looking for strong signals
    such as current_user.is_authenticated, JWT verification, authorization
    headers, or calls to recognizable authentication functions.

    The result means "authentication-like logic was detected", not
    "authentication is definitely secure".
    """

    for child in ast.walk(node):
        # ---------------------------------------------------------------
        # Detect identifiers such as:
        #
        #     current_user
        #     login_manager
        #     authorization
        # ---------------------------------------------------------------
        if isinstance(child, ast.Name):
            if child.id.lower() in AUTHENTICATION_IDENTIFIERS:
                return True

        # ---------------------------------------------------------------
        # Detect:
        #
        #     current_user.is_authenticated
        #     current_user.is_anonymous
        # ---------------------------------------------------------------
        if isinstance(child, ast.Attribute):
            attribute_name = child.attr.lower()

            if attribute_name in {
                "is_authenticated",
                "is_anonymous",
            }:
                return True

            if attribute_name in {
                "verify_jwt_in_request",
                "login_required",
                "authenticate",
            }:
                return True

        # ---------------------------------------------------------------
        # Detect authentication-related function calls.
        #
        # Examples:
        #
        #     authenticate()
        #     verify_jwt_in_request()
        #     login_required(...)
        # ---------------------------------------------------------------
        if isinstance(child, ast.Call):
            function_name: str | None = None

            if isinstance(child.func, ast.Name):
                function_name = child.func.id

            elif isinstance(child.func, ast.Attribute):
                function_name = child.func.attr

            if (
                function_name
                and function_name.lower()
                in AUTHENTICATION_FUNCTION_NAMES
            ):
                return True

    return False

def _find_authentication_hooks(
    file_path: Path,
    tree: ast.AST,
) -> dict[str, Any]:
    """
    Run the complete security analyzer against a Flask project.

    Security analysis is performed in two layers:

    1. File-level AST analysis:
    - eval()
    - exec()
    - pickle deserialization
    - debug configuration
    - hardcoded credentials

    2. Project-level analysis:
    - authentication detection
    - authenticated route detection
    - Flask-Limiter
    - recognized limiter initialization
    - custom rate limiting
    - global request hooks
    - absence of recognizable rate limiting

    Project-level analysis is performed only after the complete source tree
    has been inspected so authentication and rate-limiting implementations
    can be recognized across separate modules.
    """

    signals: dict[str, Any] = {
        "global_authentication": False,
        "blueprint_authentication": False,
        "global_locations": [],
        "blueprint_locations": [],
    }

    for node in ast.walk(tree):
        if not isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            continue

        has_before_request = False
        hook_owner: str | None = None

        for decorator in node.decorator_list:
            # -----------------------------------------------------------
            # Flask's normal syntax:
            #
            #     @app.before_request
            #     @bp.before_request
            #
            # is represented as ast.Attribute.
            #
            # A previous implementation only accepted ast.Call, which
            # caused these perfectly valid decorators to be ignored.
            # -----------------------------------------------------------
            target = decorator

            # Also unwrap callable decorator syntax such as:
            #
            #     @some_hook(...)
            #
            # so that the detector remains tolerant of decorator calls.
            if isinstance(target, ast.Call):
                target = target.func

            if not isinstance(target, ast.Attribute):
                continue

            if target.attr != "before_request":
                continue

            owner = target.value

            # We need a simple name such as:
            #
            #     app.before_request
            #     bp.before_request
            #
            # Dynamic expressions are intentionally ignored because their
            # ownership cannot be determined safely with this AST-only
            # analysis.
            if not isinstance(owner, ast.Name):
                continue

            hook_owner = owner.id
            has_before_request = True
            break

        if not has_before_request:
            continue

        # ---------------------------------------------------------------
        # A before_request hook is not automatically authentication.
        #
        # For example:
        #
        #     @app.before_request
        #     def load_cart():
        #         ...
        #
        # should NOT suppress SEC-AUTH-005.
        #
        # We therefore require recognizable authentication logic inside
        # the hook itself.
        # ---------------------------------------------------------------
        if not _contains_authentication_signal(node):
            continue

        location = {
            "file": str(file_path),
            "line": node.lineno,
            "function": node.name,
            "owner": hook_owner,
        }

        if hook_owner is None:
            continue

        normalized_owner = hook_owner.lower()

        # ---------------------------------------------------------------
        # Application-wide Flask hooks.
        #
        # Common examples:
        #
        #     @app.before_request
        #     @application.before_request
        #     @flask_app.before_request
        #
        # These protect routes across the application.
        # ---------------------------------------------------------------
        if normalized_owner in {
            "app",
            "application",
            "flask_app",
        }:
            signals["global_authentication"] = True
            signals["global_locations"].append(location)
            continue

        # ---------------------------------------------------------------
        # Blueprint-level Flask hooks.
        #
        # Common examples:
        #
        #     @bp.before_request
        #     @auth_bp.before_request
        #     @account_blueprint.before_request
        #
        # Static analysis cannot always prove exactly which routes belong
        # to a blueprint, so the project-level analyzer treats a detected
        # blueprint authentication hook as protection conservatively.
        # ---------------------------------------------------------------
        if (
            normalized_owner == "bp"
            or normalized_owner.endswith("_bp")
            or "blueprint" in normalized_owner
        ):
            signals["blueprint_authentication"] = True
            signals["blueprint_locations"].append(location)

    return signals

def _analyze_project_authentication(
    project_root: Path,
) -> dict[str, Any]:
    """
    Build project-wide authentication signals.

    The project may define authentication in one module and routes in
    another, so authentication analysis must operate across the complete
    source tree.
    """

    signals: dict[str, Any] = {
        "global_authentication": False,
        "blueprint_authentication": False,
        "route_authentication": [],
        "global_locations": [],
        "blueprint_locations": [],
    }

    try:
        python_files = project_root.rglob("*.py")
    except OSError:
        return signals

    for file_path in python_files:
        if not is_python_file(file_path):
            continue

        if should_exclude_path(file_path, project_root):
            continue

        try:
            source = file_path.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )
            tree = ast.parse(
                source,
                filename=str(file_path),
            )
        except (OSError, SyntaxError):
            continue

        hook_signals = _find_authentication_hooks(
            file_path,
            tree,
        )

        if hook_signals["global_authentication"]:
            signals["global_authentication"] = True

        if hook_signals["blueprint_authentication"]:
            signals["blueprint_authentication"] = True

        signals["global_locations"].extend(
            hook_signals["global_locations"]
        )

        signals["blueprint_locations"].extend(
            hook_signals["blueprint_locations"]
        )

        # ---------------------------------------------------------------
        # Collect directly authenticated routes.
        # ---------------------------------------------------------------
        for node in ast.walk(tree):
            if not isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue

            if not _has_authentication_decorator(node):
                continue

            for decorator in node.decorator_list:
                route = _extract_route_path(decorator)

                if route:
                    signals["route_authentication"].append(
                        {
                            "route": route,
                            "file": str(file_path),
                            "line": node.lineno,
                            "function": node.name,
                        }
                    )

    return signals


def _analyze_project_authentication_routes(
    project_root: Path,
    auth_signals: dict[str, Any],
) -> list[Finding]:
    """
    Analyze sensitive routes using project-wide authentication signals.

    A route is considered protected when authentication is detected:

    1. directly on the route,
    2. globally through app.before_request, or
    3. through a recognized blueprint-level authentication hook.

    Because blueprint ownership cannot always be statically proven, a
    blueprint-level signal suppresses the finding conservatively rather
    than generating a potentially incorrect vulnerability report.
    """

    findings: list[Finding] = []

    try:
        python_files = project_root.rglob("*.py")
    except OSError:
        return findings

    # A global authentication hook protects routes throughout the
    # application unless there is explicit evidence that a route is
    # deliberately excluded.
    global_authentication = bool(
        auth_signals.get("global_authentication")
    )

    # Blueprint-level authentication is also treated as protection for now.
    # A later phase can map blueprint names to routes precisely.
    blueprint_authentication = bool(
        auth_signals.get("blueprint_authentication")
    )

    for file_path in python_files:
        if not is_python_file(file_path):
            continue

        if should_exclude_path(file_path, project_root):
            continue

        try:
            source = file_path.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )
            tree = ast.parse(
                source,
                filename=str(file_path),
            )
        except (OSError, SyntaxError):
            continue

        for node in ast.walk(tree):
            if not isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue

            routes: list[str] = []

            for decorator in node.decorator_list:
                route = _extract_route_path(decorator)

                if route:
                    routes.append(route)

            if not routes:
                continue

            # Direct route-level authentication always wins.
            if _has_authentication_decorator(node):
                continue

            # Project-wide authentication provides broader protection.
            if global_authentication:
                continue

            # Blueprint-level authentication is currently treated as
            # sufficient protection because statically determining exactly
            # which blueprint owns every route is not always possible.
            if blueprint_authentication:
                continue

            for route in routes:
                if not _is_sensitive_auth_route(route):
                    continue

                findings.append(
                    Finding(
                        id="SEC-AUTH-005",
                        category="security",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        title="Sensitive route has no detected authentication",
                        description=(
                            f"The sensitive route {route!r} handled by "
                            f"{node.name} in {file_path.name} has no "
                            "recognizable authentication or authorization "
                            "mechanism at the route or project level."
                        ),
                        recommendation=(
                            "Protect this route with an explicit "
                            "authentication or authorization mechanism, "
                            "or verify that equivalent protection is "
                            "enforced globally."
                        ),
                        file=str(file_path),
                        line=node.lineno,
                        metadata={
                            "route": route,
                            "function": node.name,
                            "authentication_detected": False,
                            "global_authentication_detected": False,
                            "blueprint_authentication_detected": False,
                            "requires_authentication_review": True,
                        },
                    )
                )

    return findings


def _looks_like_blueprint_before_request(
    decorator: ast.expr,
) -> bool:
    """Return True when a decorator appears to be blueprint.before_request."""

    if not isinstance(decorator, ast.Attribute):
        if not isinstance(decorator, ast.Call):
            return False

        decorator = decorator.func

    if not isinstance(decorator, ast.Attribute):
        return False

    return decorator.attr == "before_request"


def _function_contains_authentication_evidence(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """
    Determine whether a function contains recognizable authentication logic.

    Merely having a before_request hook is insufficient. We require evidence
    such as ``current_user.is_authenticated`` or a recognizable authentication
    helper/decorator.
    """

    authentication_names = {
        "current_user",
        "login_required",
        "login_user",
        "logout_user",
        "auth_required",
        "authenticate",
        "authentication",
        "authenticated",
    }

    for node in ast.walk(function_node):
        # Detect:
        #
        #     current_user.is_authenticated
        if isinstance(node, ast.Attribute):
            if node.attr in {
                "is_authenticated",
                "is_anonymous",
            }:
                return True

        # Detect recognizable authentication calls/names.
        if isinstance(node, ast.Name):
            if node.id.lower() in authentication_names:
                return True

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id.lower() in authentication_names:
                    return True

            if isinstance(node.func, ast.Attribute):
                if node.func.attr.lower() in authentication_names:
                    return True

    return False