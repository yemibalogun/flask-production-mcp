
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


def _looks_like_secret_name(name: str) -> bool:
    """
    Determine whether a variable name probably represents secret material.

    Matching is deliberately conservative. Generic names such as ``key`` or
    ``token`` alone are not enough because they are frequently used for
    harmless application data.
    """

    normalized = _normalize_secret_name(name)

    if normalized in {
        "secret",
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "client_secret",
        "private_key",
        "access_token",
        "refresh_token",
        "database_url",
        "db_url",
        "dsn",
    }:
        return True

    return any(
        pattern in normalized
        for pattern in SECRET_NAME_PATTERNS
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


def _looks_like_secret_value(value: str) -> bool:
    """
    Determine whether a literal string has characteristics of a secret.

    Short strings are ignored because values such as ``"admin"`` or
    ``"localhost"`` are unlikely to be useful credentials.
    """

    stripped = value.strip()

    if _looks_like_placeholder(stripped):
        return False

    if len(stripped) < 8:
        return False

    return True


def _secret_value_confidence(
    variable_name: str,
    value: str,
) -> Confidence:
    """
    Determine confidence that a literal value is a real secret.

    Provider-specific prefixes are the strongest signal. Explicit secret
    configuration names are also treated as high confidence because names
    such as FLUTTERWAVE_SECRET_KEY or JWT_SECRET strongly indicate that the
    associated literal is credential material.

    The value itself is never included in the finding.
    """

    # Known provider/token prefixes provide very strong evidence that the
    # literal is an actual credential rather than ordinary configuration.
    if any(
        value.startswith(prefix)
        for prefix in SECRET_VALUE_PREFIXES
    ):
        return Confidence.HIGH

    normalized_name = _normalize_secret_name(variable_name)

    # Explicit secret-bearing configuration names should also receive high
    # confidence even when the provider does not expose a recognizable
    # prefix. This covers credentials such as:
    #
    #     FLUTTERWAVE_SECRET_KEY = "..."
    #     FLUTTERWAVE_SECRET_HASH = "..."
    #     JWT_SECRET = "..."
    #     STRIPE_SECRET_KEY = "..."
    #
    # The detector intentionally requires a sufficiently secret-like value
    # before reaching this function, so generic configuration values are not
    # promoted to high confidence here.
    strong_secret_patterns = (
        "secret",
        "private_key",
        "client_secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "auth_token",
        "password",
        "passwd",
    )

    if any(
        pattern in normalized_name
        for pattern in strong_secret_patterns
    ):
        return Confidence.HIGH

    # Database connection strings are sensitive, but they can sometimes
    # contain development credentials or non-secret connection information.
    # Keep them at medium confidence unless stronger evidence exists.
    if normalized_name in {
        "database_url",
        "db_url",
        "dsn",
    }:
        return Confidence.MEDIUM

    return Confidence.MEDIUM


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


def _is_sensitive_route(route: str) -> bool:
    """Determine whether a route deserves rate-limit scrutiny."""

    normalized = route.lower().rstrip("/") or "/"

    return any(
        pattern in normalized
        for pattern in SENSITIVE_ROUTE_PATTERNS
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
            encoding="utf-8",
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

    # Detect sensitive routes that have no recognizable authentication
    # decorator. This is separate from rate-limit analysis because a route
    # can be authenticated but still lack abuse protection.
    findings.extend(
        _find_unprotected_sensitive_routes_auth(
            file_path,
            tree,
        )
    )

    # Rate-limit analysis remains project-level. A limiter can be initialized
    # in extensions.py and consumed from routes.py, so checking it here would
    # create false positives.
    return findings


def _is_analyzer_test_file(
    file_path: Path,
) -> bool:
    """
    Identify files that intentionally contain dangerous patterns.

    The MCP's own analyzer test fixtures may contain eval(), exec(), or
    pickle examples deliberately. Those examples must not cause the MCP
    to report itself as vulnerable when developers run:

        audit_security(".")

    This is deliberately narrow rather than excluding the entire
    analyzer package.
    """

    filename = file_path.name.lower()

    return (
        filename.startswith("test_")
        or filename.endswith("_test.py")
    )


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


def _find_environment_file(
    project_root: Path,
) -> list[Finding]:
    """Detect environment files that may contain application secrets."""

    env_file = project_root / ".env"

    if not env_file.is_file():
        return []

    return [
        Finding(
            id="SEC-CONFIG-002",
            category="security",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            title="A .env file exists in the project",
            description=(
                "The project contains a .env file. Environment files "
                "commonly contain credentials, API keys, database "
                "passwords, and other sensitive configuration."
            ),
            recommendation=(
                "Ensure .env is excluded from version control using "
                ".gitignore. Production secrets should preferably be "
                "provided through environment variables or a dedicated "
                "secret-management system."
            ),
            file=str(env_file),
            line=None,
            metadata={
                "filename": ".env",
                "requires_gitignore_review": True,
            },
        )
    ]


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


def _check_rate_limiting(tree: ast.AST) -> Finding | None:
    """
    Create a finding when no recognizable rate limiting is present.
    """

    if _find_rate_limit_configuration(tree):
        return None

    return Finding(
        id="SEC-AUTH-002",
        category="security",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        title="Rate limiting was not detected",
        description=(
            "No recognizable rate-limiting implementation was detected "
            "in the application. Authentication, OTP, password reset, "
            "account recovery, payment, and other abuse-sensitive "
            "endpoints may be vulnerable to automated requests."
        ),
        recommendation=(
            "Implement rate limiting for authentication, OTP, password "
            "reset, account recovery, payment, and other abuse-sensitive "
            "endpoints. Flask-Limiter or an equivalent distributed "
            "rate-limiting solution can be used."
        ),
        file=None,
        line=None,
        metadata={
            "requires_route_review": True,
        },
    )



def _find_unprotected_sensitive_routes(
    file_path: Path,
    tree: ast.AST,
) -> list[Finding]:
    """
    Find sensitive Flask routes without detectable rate limiting.

    Static analysis cannot determine whether protection is supplied by:
    - application-wide Flask-Limiter configuration,
    - middleware,
    - an API gateway,
    - a reverse proxy,
    - or another infrastructure component.

    Findings therefore identify missing *detectable* protection rather
    than claiming that a vulnerability definitely exists.
    """

    findings: list[Finding] = []

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

        has_rate_limit, limiter_name = _has_rate_limit_decorator(node)

        if has_rate_limit:
            continue

        if _is_rate_limit_exempt(node):
            # Explicit exemptions should not be reported as missing
            # protection. A future analyzer can separately report
            # potentially dangerous exemptions.
            continue

        for route in routes:
            risk = _classify_route_risk(route)

            if risk is None:
                continue

            severity = (
                Severity.HIGH
                if risk == RouteRisk.HIGH
                else Severity.MEDIUM
            )

            findings.append(
                Finding(
                    id="SEC-AUTH-003",
                    category="security",
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    title="Sensitive route has no detected rate limit",
                    description=(
                        f"The {risk.value}-risk route {route!r} "
                        f"handled by {node.name} in {file_path.name} "
                        "has no detectable route-level rate-limit "
                        "decorator. Static analysis cannot determine "
                        "whether equivalent protection exists globally "
                        "or at the infrastructure layer."
                    ),
                    recommendation=(
                        "Apply an explicit rate limit to this route "
                        "or verify that equivalent application-wide, "
                        "middleware, gateway, or reverse-proxy "
                        "rate limiting is enforced."
                    ),
                    file=str(file_path),
                    line=node.lineno,
                    metadata={
                        "route": route,
                        "function": node.name,
                        "risk": risk.value,
                        "rate_limit": False,
                        "requires_route_review": True,
                    },
                )
            )

    return findings

def _find_unprotected_sensitive_routes_auth(
    file_path: Path,
    tree: ast.AST,
) -> list[Finding]:
    """
    Find sensitive Flask routes without detectable authentication.

    This is intentionally conservative. Static analysis cannot prove that
    authentication is absent because protection may be supplied through:

    - application-wide middleware,
    - blueprint-level hooks,
    - before_request handlers,
    - Flask-Login configuration,
    - API gateways,
    - reverse proxies,
    - custom decorators whose implementation is outside the file.

    Therefore this finding means that no recognizable authentication
    decorator was detected directly on the route.
    """

    findings: list[Finding] = []

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

        # ---------------------------------------------------------------
        # Look for recognizable authentication/authorization decorators.
        #
        # We deliberately recognize common Flask authentication patterns
        # without requiring a particular authentication library.
        # ---------------------------------------------------------------
        if _has_authentication_decorator(node):
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
                        "decorator. Static analysis cannot determine "
                        "whether authentication is enforced globally "
                        "or by infrastructure."
                    ),
                    recommendation=(
                        "Protect this route with an explicit authentication "
                        "or authorization mechanism, or verify that "
                        "equivalent protection is enforced globally."
                    ),
                    file=str(file_path),
                    line=node.lineno,
                    metadata={
                        "route": route,
                        "function": node.name,
                        "authentication_detected": False,
                        "requires_authentication_review": True,
                    },
                )
            )

    return findings

def _has_authentication_decorator(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """
    Determine whether a route has a recognizable authentication decorator.

    The detector intentionally supports common decorator names rather than
    tying the analyzer to one authentication framework.
    """

    recognized_names: frozenset[str] = frozenset(
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

    for decorator in function_node.decorator_list:
        name = _decorator_name(decorator)

        if not name:
            continue

        # ``login_required`` and ``login_manager.login_required`` should
        # both resolve to the final decorator component.
        base_name = name.split(".")[-1].lower()

        if base_name in recognized_names:
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
                encoding="utf-8",
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