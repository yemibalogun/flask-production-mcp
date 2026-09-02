"""Static analysis of Jinja/HTML templates for Flask projects.

Generic Python SAST never looks at templates, yet that is where a whole
class of real production failures lives: a POST form with no CSRF field
(a guaranteed 400 once CSRF protection is on), ``| safe`` on user data
(stored XSS), disabled autoescaping, and ``url_for()`` calls that point at
endpoints which do not exist.

The analyzer works on the template source text rather than a parsed Jinja
AST. Templates routinely use project-specific tags/filters and third-party
extensions (flask-caching, flask-assets, ...) that would make a strict
parse fail; text scanning degrades gracefully instead.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from flask_production_mcp.analyzers.exclusions import iter_template_files
from flask_production_mcp.models.findings import (
    Confidence,
    Finding,
    Severity,
)

# A <form ...> ... </form> block. Non-greedy, case-insensitive, spans lines.
_FORM_BLOCK = re.compile(
    r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form\s*>",
    re.IGNORECASE | re.DOTALL,
)

_METHOD_ATTR = re.compile(
    r"""method\s*=\s*['"]?\s*(post|put|patch|delete)\b""",
    re.IGNORECASE,
)

_ACTION_ATTR = re.compile(
    r"""action\s*=\s*['"]\s*(?P<url>[^'"]*)""",
    re.IGNORECASE,
)

# Any of these appearing inside a <form> body is treated as a CSRF token.
_CSRF_MARKERS = re.compile(
    r"""
      csrf_token            # {{ csrf_token() }} or name="csrf_token"
    | hidden_tag            # {{ form.hidden_tag() }}
    | csrf_field            # {{ csrf_field() }}
    | \{\{\s*form\s*\}\}    # {{ form }} renders the whole WTForm
    | \{\{\s*form\.csrf     # {{ form.csrf_token }}
    """,
    re.IGNORECASE | re.VERBOSE,
)

# {{ <expr> | safe }}  (optionally with chained filters before safe)
_SAFE_FILTER = re.compile(
    r"\{\{\s*(?P<expr>.*?)\|\s*safe\s*(?:\|[^}]*)?\}\}",
    re.DOTALL,
)

_AUTOESCAPE_FALSE = re.compile(
    r"\{%\s*autoescape\s+(?:false|False|0|none|None)\s*%\}",
)

_URL_FOR = re.compile(
    r"""url_for\(\s*(['"])(?P<endpoint>[A-Za-z_][\w.]*)\1""",
)

_STRING_LITERAL = re.compile(r"""^\s*(['"]).*\1\s*$""", re.DOTALL)


def _line_of(text: str, index: int) -> int:
    """1-based line number of the character offset ``index``."""

    return text.count("\n", 0, index) + 1


def _find_missing_csrf(
    file_path: Path,
    source: str,
) -> list[Finding]:
    findings: list[Finding] = []

    for match in _FORM_BLOCK.finditer(source):
        attrs = match.group("attrs")
        body = match.group("body")

        if not _METHOD_ATTR.search(attrs):
            # No state-changing method -> CSRF not required.
            continue

        action = _ACTION_ATTR.search(attrs)
        if action:
            url = action.group("url").strip()
            if url.startswith(("http://", "https://", "//")):
                # Posts to a third-party endpoint; not our CSRF surface.
                continue

        if _CSRF_MARKERS.search(body):
            continue

        # A token could legitimately live in an included partial or be
        # emitted by a form macro; lower the confidence in that case.
        uncertain = (
            "{% include" in body
            or "{%- include" in body
            or re.search(r"\{\{\s*form\.", body) is not None
        )

        findings.append(
            Finding(
                id="TMPL-CSRF-001",
                category="template",
                severity=Severity.HIGH,
                confidence=(
                    Confidence.MEDIUM if uncertain else Confidence.HIGH
                ),
                title="POST form has no CSRF token field",
                description=(
                    "A state-changing <form> does not contain a CSRF token "
                    "(csrf_token(), form.hidden_tag(), or an equivalent "
                    "hidden field). With Flask-WTF CSRF protection enabled "
                    "this form's submissions are rejected with HTTP 400; "
                    "without protection it is exposed to cross-site request "
                    "forgery."
                ),
                recommendation=(
                    "Add a hidden CSRF field inside the form, e.g. "
                    '<input type="hidden" name="csrf_token" '
                    'value="{{ csrf_token() }}"> or {{ form.hidden_tag() }}.'
                ),
                file=str(file_path),
                line=_line_of(source, match.start()),
                metadata={
                    "form_tag": ("<form" + attrs + ">").strip()[:200],
                },
            )
        )

    return findings


def _find_unsafe_markup(
    file_path: Path,
    source: str,
) -> list[Finding]:
    findings: list[Finding] = []

    for match in _SAFE_FILTER.finditer(source):
        expr = match.group("expr").strip()

        if not expr or _STRING_LITERAL.match(expr):
            # `{{ "literal" | safe }}` is harmless.
            continue

        findings.append(
            Finding(
                id="TMPL-SAFE-001",
                category="template",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                title="Autoescaping bypassed with the `safe` filter",
                description=(
                    f"The expression `{expr[:80]}` is rendered through the "
                    "`safe` filter, which disables HTML autoescaping. If any "
                    "part of that value is influenced by user input this is "
                    "a stored/reflected XSS vector."
                ),
                recommendation=(
                    "Remove the `safe` filter and let Jinja autoescape the "
                    "value. If raw HTML is genuinely required, sanitise it "
                    "server-side (e.g. with bleach) before rendering and "
                    "keep the trusted markup in a dedicated variable."
                ),
                file=str(file_path),
                line=_line_of(source, match.start()),
                metadata={"expression": expr[:200]},
            )
        )

    for match in _AUTOESCAPE_FALSE.finditer(source):
        findings.append(
            Finding(
                id="TMPL-SAFE-002",
                category="template",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Autoescaping disabled for a template block",
                description=(
                    "An `{% autoescape false %}` block turns off HTML "
                    "escaping for everything it contains. Every variable "
                    "rendered inside it is a potential XSS sink."
                ),
                recommendation=(
                    "Remove the autoescape-false block. Escape by default "
                    "and apply `| safe` only to individually vetted, "
                    "server-sanitised values."
                ),
                file=str(file_path),
                line=_line_of(source, match.start()),
                metadata={},
            )
        )

    return findings


def _normalise_endpoints(
    known_endpoints: Iterable[str] | None,
) -> set[str] | None:
    if known_endpoints is None:
        return None

    endpoints = set(known_endpoints)
    endpoints.add("static")
    return endpoints


def _find_broken_url_for(
    file_path: Path,
    source: str,
    endpoints: set[str] | None,
) -> list[Finding]:
    if endpoints is None:
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for match in _URL_FOR.finditer(source):
        endpoint = match.group("endpoint")

        # Blueprint-relative names (`.name`) resolve at runtime against the
        # current blueprint; we cannot check those statically.
        if endpoint.startswith("."):
            continue

        if endpoint in endpoints or endpoint.endswith(".static"):
            continue

        line = _line_of(source, match.start())
        if (endpoint, line) in seen:
            continue
        seen.add((endpoint, line))

        findings.append(
            Finding(
                id="TMPL-URL-001",
                category="template",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title=f"url_for() references unknown endpoint '{endpoint}'",
                description=(
                    f"The template calls url_for('{endpoint}') but no route "
                    "with that endpoint was discovered in the project. At "
                    "runtime this raises BuildError and returns HTTP 500."
                ),
                recommendation=(
                    "Check the endpoint name against the route/blueprint "
                    "that defines it (usually 'blueprint_name.view_name'). "
                    "If the blueprint is registered dynamically this may be "
                    "a false positive."
                ),
                file=str(file_path),
                line=line,
                metadata={"endpoint": endpoint},
            )
        )

    return findings


def analyze_templates(
    project_root: Path,
    known_endpoints: Iterable[str] | None = None,
) -> list[Finding]:
    """
    Scan a project's Jinja/HTML templates for production-readiness issues.

    Pass ``known_endpoints`` (e.g. from the Flask analyzer) to also flag
    ``url_for()`` calls that target endpoints which do not exist.
    """

    root = Path(project_root).expanduser().resolve()
    endpoints = _normalise_endpoints(known_endpoints)

    findings: list[Finding] = []

    for template in iter_template_files(root):
        try:
            source = template.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )
        except OSError:
            continue

        findings.extend(_find_missing_csrf(template, source))
        findings.extend(_find_unsafe_markup(template, source))
        findings.extend(_find_broken_url_for(template, source, endpoints))

    return findings
