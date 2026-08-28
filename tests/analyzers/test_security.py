"""Tests for the Flask Production MCP security analyzer."""

from __future__ import annotations

from pathlib import Path

from flask_production_mcp.analyzers.security import (
    _analyze_project_rate_limiting,
    analyze_python_file,
    analyze_security,
)
from flask_production_mcp.models.findings import Severity


def write_python_file(
    tmp_path: Path,
    relative_path: str,
    source: str,
) -> Path:
    """Create a temporary Python source file for AST analysis."""

    file_path = tmp_path / relative_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(source, encoding="utf-8")

    return file_path


def finding_ids(findings: list) -> set[str]:
    """Return finding IDs for concise assertions."""

    return {finding.id for finding in findings}


def test_analyze_python_file_detects_eval(
    tmp_path: Path,
) -> None:
    """Dangerous eval() calls should be detected."""

    file_path = write_python_file(
        tmp_path,
        "app/routes.py",
        """
def process(value):
    return eval(value)
""",
    )

    findings = analyze_python_file(file_path)

    assert any(
        finding.id == "SEC-CODE-001"
        for finding in findings
    )


def test_analyze_python_file_detects_exec(
    tmp_path: Path,
) -> None:
    """Dangerous exec() calls should be detected."""

    file_path = write_python_file(
        tmp_path,
        "app/routes.py",
        """
def process(value):
    exec(value)
""",
    )

    findings = analyze_python_file(file_path)

    # exec() intentionally has its own, more severe finding ID.
    assert any(
        finding.id == "SEC-CODE-002"
        for finding in findings
    )


def test_analyze_python_file_detects_pickle_loads(
    tmp_path: Path,
) -> None:
    """Unsafe pickle deserialization should be detected."""

    file_path = write_python_file(
        tmp_path,
        "app/services/cache.py",
        """
import pickle


def load_data(data):
    return pickle.loads(data)
""",
    )

    findings = analyze_python_file(file_path)

    assert any(
        "pickle" in finding.title.lower()
        or "pickle" in finding.description.lower()
        for finding in findings
    )


def test_analyze_python_file_detects_hardcoded_secret(
    tmp_path: Path,
) -> None:
    """Real-looking hardcoded credentials should be detected."""

    file_path = write_python_file(
        tmp_path,
        "app/config.py",
        """
SECRET_KEY = "super-secret-production-value-123456"
API_KEY = "sk_live_123456789abcdef"
""",
    )

    findings = analyze_python_file(file_path)

    assert any(
        "secret" in finding.title.lower()
        or "credential" in finding.title.lower()
        for finding in findings
    )


def test_analyze_python_file_ignores_secret_placeholder(
    tmp_path: Path,
) -> None:
    """Obvious placeholders should not trigger secret findings."""

    file_path = write_python_file(
        tmp_path,
        "app/config.py",
        """
SECRET_KEY = "your-secret-key"
API_KEY = "placeholder"
""",
    )

    findings = analyze_python_file(file_path)

    secret_findings = [
        finding
        for finding in findings
        if "secret" in finding.title.lower()
        or "credential" in finding.title.lower()
    ]

    assert not secret_findings


def test_project_without_rate_limiting_gets_sec_auth_002(
    tmp_path: Path,
) -> None:
    """Projects with no recognizable limiter should receive SEC-AUTH-002."""

    write_python_file(
        tmp_path,
        "app/routes.py",
        """
from flask import Blueprint

bp = Blueprint("main", __name__)


@bp.route("/login", methods=["POST"])
def login():
    return "ok"
""",
    )

    findings = _analyze_project_rate_limiting(tmp_path)

    assert "SEC-AUTH-002" in finding_ids(findings)

    finding = next(
        finding
        for finding in findings
        if finding.id == "SEC-AUTH-002"
    )

    assert finding.severity == Severity.HIGH


def test_flask_limiter_initialization_is_recognized(
    tmp_path: Path,
) -> None:
    """Flask-Limiter initialization should suppress the missing-limiter finding."""

    write_python_file(
        tmp_path,
        "app/extensions.py",
        """
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per minute"],
)
""",
    )

    findings = _analyze_project_rate_limiting(tmp_path)

    assert "SEC-AUTH-002" not in finding_ids(findings)


def test_flask_limiter_route_application_is_recognized(
    tmp_path: Path,
) -> None:
    """A recognized limiter applied to a route should count as protection."""

    write_python_file(
        tmp_path,
        "app/extensions.py",
        """
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
)
""",
    )

    write_python_file(
        tmp_path,
        "app/routes.py",
        """
from flask import Blueprint

from app.extensions import limiter

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    return "ok"
""",
    )

    findings = _analyze_project_rate_limiting(tmp_path)

    assert "SEC-AUTH-002" not in finding_ids(findings)


def test_custom_rate_limiter_application_is_recognized(
    tmp_path: Path,
) -> None:
    """Recognizable custom rate-limit decorators should count as protection."""

    write_python_file(
        tmp_path,
        "app/security.py",
        """
def rate_limit(limit):
    def decorator(function):
        return function

    return decorator
""",
    )

    write_python_file(
        tmp_path,
        "app/routes.py",
        """
from flask import Blueprint

from app.security import rate_limit

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
@rate_limit("5/minute")
def login():
    return "ok"
""",
    )

    findings = _analyze_project_rate_limiting(tmp_path)

    assert "SEC-AUTH-002" not in finding_ids(findings)


def test_generic_before_request_is_not_rate_limiting(
    tmp_path: Path,
) -> None:
    """
    A generic Flask request hook must not be incorrectly classified
    as rate limiting.
    """

    write_python_file(
        tmp_path,
        "app/hooks.py",
        """
from flask import Flask

app = Flask(__name__)


@app.before_request
def enforce_session():
    pass
""",
    )

    findings = _analyze_project_rate_limiting(tmp_path)

    ids = finding_ids(findings)

    # A generic request hook is not evidence of actual rate limiting.
    # The analyzer deliberately reports this as a manual-review finding.
    assert "SEC-AUTH-004" in ids
    assert "SEC-AUTH-002" not in ids


def test_global_hook_with_rate_limit_logic_is_recognized(
    tmp_path: Path,
) -> None:
    """A global request hook containing explicit rate-limit logic is recognized."""

    write_python_file(
        tmp_path,
        "app/hooks.py",
        """
from flask import Flask

app = Flask(__name__)


def check_rate_limit():
    return True


@app.before_request
def enforce_rate_limit():
    if not check_rate_limit():
        return "Too many requests", 429
""",
    )

    findings = _analyze_project_rate_limiting(tmp_path)

    assert "SEC-AUTH-002" not in finding_ids(findings)


def test_analyze_security_handles_missing_project(
    tmp_path: Path,
) -> None:
    """A missing project path should return a failed AuditResult safely."""

    missing_path = tmp_path / "does-not-exist"

    result = analyze_security(missing_path)

    assert result.success is False
    assert result.score == 0
    assert result.findings == []
    assert result.errors


def test_analyze_security_handles_empty_project(
    tmp_path: Path,
) -> None:
    """An empty project should still produce a valid audit result."""

    result = analyze_security(tmp_path)

    assert result.success is True
    assert result.project_path == str(tmp_path.resolve())
    assert isinstance(result.findings, list)
    assert isinstance(result.recommendations, list)


def test_analyze_security_does_not_duplicate_project_rate_limit_finding(
    tmp_path: Path,
) -> None:
    """
    SEC-AUTH-002 must be generated once at project level rather than once
    for every Python file.
    """

    write_python_file(
        tmp_path,
        "app/routes.py",
        """
def login():
    return "ok"
""",
    )

    write_python_file(
        tmp_path,
        "app/users.py",
        """
def create_user():
    return "ok"
""",
    )

    write_python_file(
        tmp_path,
        "app/payments.py",
        """
def checkout():
    return "ok"
""",
    )

    result = analyze_security(tmp_path)

    rate_limit_findings = [
        finding
        for finding in result.findings
        if finding.id == "SEC-AUTH-002"
    ]

    assert len(rate_limit_findings) == 1


def test_sensitive_route_without_authentication_is_detected(
    tmp_path: Path,
) -> None:
    """Sensitive authenticated routes should not be left unprotected."""

    write_python_file(
        tmp_path,
        "app/routes.py",
        """
from flask import Blueprint

bp = Blueprint("account", __name__)


@bp.route("/account/profile")
def profile():
    return "profile"
""",
    )

    result = analyze_security(tmp_path)

    findings = [
        finding
        for finding in result.findings
        if finding.id == "SEC-AUTH-005"
    ]

    assert findings
    assert findings[0].severity == Severity.HIGH
    assert findings[0].file is not None
    assert findings[0].line is not None

def test_login_required_protects_sensitive_route(
    tmp_path: Path,
) -> None:
    """login_required should prevent a false positive on sensitive routes."""

    write_python_file(
        tmp_path,
        "app/routes.py",
        """
from flask import Blueprint
from flask_login import login_required

bp = Blueprint("account", __name__)


@bp.route("/account/profile")
@login_required
def profile():
    return "profile"
""",
    )

    result = analyze_security(tmp_path)

    assert not any(
        finding.id == "SEC-AUTH-005"
        for finding in result.findings
    )

def test_flask_login_initialization_is_recognized(
    tmp_path: Path,
) -> None:
    """Flask-Login initialization should be recognized."""

    write_python_file(
        tmp_path,
        "app/extensions.py",
        """
from flask_login import LoginManager

login_manager = LoginManager()
""",
    )

    result = analyze_security(tmp_path)

    assert result.success is True

def test_public_route_is_not_flagged_as_missing_authentication(
    tmp_path: Path,
) -> None:
    """Ordinary public routes should not require authentication."""

    write_python_file(
        tmp_path,
        "app/routes.py",
        """
from flask import Blueprint

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return "hello"
""",
    )

    result = analyze_security(tmp_path)

    assert not any(
        finding.id == "SEC-AUTH-005"
        for finding in result.findings
    )

def test_login_route_is_not_flagged_as_missing_authentication(
    tmp_path: Path,
) -> None:
    """The login endpoint must remain publicly accessible."""

    write_python_file(
        tmp_path,
        "app/auth.py",
        """
from flask import Blueprint

bp = Blueprint("auth", __name__)


@bp.post("/login")
def login():
    return "ok"
""",
    )

    result = analyze_security(tmp_path)

    assert not any(
        finding.id == "SEC-AUTH-005"
        for finding in result.findings
    )

def test_custom_auth_decorator_protects_sensitive_route(
    tmp_path: Path,
) -> None:
    """Recognizable custom authentication decorators should be respected."""

    write_python_file(
        tmp_path,
        "app/security.py",
        """
def login_required(function):
    return function
""",
    )

    write_python_file(
        tmp_path,
        "app/routes.py",
        """
from flask import Blueprint
from app.security import login_required

bp = Blueprint("account", __name__)


@bp.route("/account/profile")
@login_required
def profile():
    return "profile"
""",
    )

    result = analyze_security(tmp_path)

    assert not any(
        finding.id == "SEC-AUTH-005"
        for finding in result.findings
    )