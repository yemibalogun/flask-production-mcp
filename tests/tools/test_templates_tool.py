"""Tests for the audit_templates MCP tool and template analyzer."""

from __future__ import annotations

from pathlib import Path

from flask_production_mcp.analyzers.templates import analyze_templates
from flask_production_mcp.tools.templates import audit_templates


def _write(project: Path, rel: str, content: str) -> Path:
    path = project / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_flags_post_form_without_csrf(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "templates/delete.html",
        '<form method="post" action="/x/1/delete">'
        "<button>Delete</button></form>",
    )

    findings = analyze_templates(tmp_path)

    assert [f.id for f in findings] == ["TMPL-CSRF-001"]
    assert findings[0].severity.value == "high"
    assert findings[0].confidence.value == "high"


def test_accepts_form_with_csrf_token(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "templates/ok.html",
        '<form method="post" action="/x">'
        '<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">'
        "<button>Go</button></form>",
    )
    _write(
        tmp_path,
        "templates/hidden_tag.html",
        '<form method="post">{{ form.hidden_tag() }}<button>Go</button></form>',
    )

    assert analyze_templates(tmp_path) == []


def test_ignores_get_forms_and_external_posts(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "templates/search.html",
        '<form method="get" action="/search"><input name="q"></form>',
    )
    _write(
        tmp_path,
        "templates/external.html",
        '<form method="post" action="https://pay.example.com/checkout">'
        "<button>Pay</button></form>",
    )

    assert analyze_templates(tmp_path) == []


def test_flags_safe_filter_on_dynamic_value(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "templates/bio.html",
        "<div>{{ user.bio | safe }}</div>\n"
        '<div>{{ "<b>ok</b>" | safe }}</div>',
    )

    findings = analyze_templates(tmp_path)

    assert [f.id for f in findings] == ["TMPL-SAFE-001"]
    assert "user.bio" in findings[0].metadata["expression"]


def test_flags_autoescape_false(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "templates/raw.html",
        "{% autoescape false %}{{ x }}{% endautoescape %}",
    )

    findings = analyze_templates(tmp_path)

    assert [f.id for f in findings] == ["TMPL-SAFE-002"]


def test_flags_unknown_url_for_endpoint_only_with_known_set(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "templates/nav.html",
        "<a href=\"{{ url_for('shop.index') }}\">home</a>\n"
        "<a href=\"{{ url_for('shop.gone') }}\">x</a>",
    )

    # Without a known-endpoint set, url_for is not checked.
    assert analyze_templates(tmp_path) == []

    findings = analyze_templates(
        tmp_path, known_endpoints={"shop.index", "shop"}
    )
    assert [f.id for f in findings] == ["TMPL-URL-001"]
    assert findings[0].metadata["endpoint"] == "shop.gone"


def test_audit_templates_tool_shape(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "templates/delete.html",
        '<form method="post"><button>Delete</button></form>',
    )

    result = audit_templates(str(tmp_path))

    assert result["success"] is True
    for key in ("score", "summary", "findings", "recommendations", "errors"):
        assert key in result
    assert any(f["id"] == "TMPL-CSRF-001" for f in result["findings"])


def test_audit_templates_missing_path() -> None:
    result = audit_templates("/no/such/dir/x")

    assert result["success"] is False
    assert "error" in result
