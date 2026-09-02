"""Tests for project configuration loading and finding post-processing."""

from __future__ import annotations

from pathlib import Path

from flask_production_mcp.config import Config, load_config
from flask_production_mcp.models.findings import (
    Confidence,
    Finding,
    Severity,
)


def _finding(rule_id: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        id=rule_id,
        category="test",
        severity=severity,
        confidence=Confidence.MEDIUM,
        title="t",
        description="d",
        recommendation="r",
    )


def test_defaults_when_no_config(tmp_path: Path) -> None:
    config = load_config(tmp_path)

    assert config.fail_on == "blockers"
    assert config.category_floor == 50
    assert config.scan_dependencies is True
    assert config.run_bandit is True
    assert config.source is None


def test_loads_dedicated_toml(tmp_path: Path) -> None:
    (tmp_path / "flask-production.toml").write_text(
        'fail_on = "advisories"\n'
        "category_floor = 70\n"
        "scan_dependencies = false\n"
        'ignore = ["DB-PERF-001"]\n'
        "\n[severity]\n"
        '"TMPL-SAFE-001" = "medium"\n',
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.fail_on == "advisories"
    assert config.category_floor == 70
    assert config.scan_dependencies is False
    assert "DB-PERF-001" in config.ignore
    assert config.severity_overrides["TMPL-SAFE-001"] is Severity.MEDIUM


def test_loads_pyproject_section(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.flask-production]\n"
        'select = ["TMPL-CSRF-001"]\n'
        "run_bandit = false\n",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.select == frozenset({"TMPL-CSRF-001"})
    assert config.run_bandit is False


def test_dedicated_toml_wins_over_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.flask-production]\nfail_on = "any"\n', encoding="utf-8"
    )
    (tmp_path / "flask-production.toml").write_text(
        'fail_on = "never"\n', encoding="utf-8"
    )

    assert load_config(tmp_path).fail_on == "never"


def test_apply_ignore_and_select() -> None:
    findings = [_finding("A"), _finding("B"), _finding("C")]

    assert {f.id for f in Config(ignore=frozenset({"B"})).apply(findings)} == {
        "A",
        "C",
    }
    assert {
        f.id for f in Config(select=frozenset({"A", "C"})).apply(findings)
    } == {"A", "C"}


def test_apply_severity_override() -> None:
    findings = [_finding("A", Severity.HIGH)]
    config = Config(severity_overrides={"A": Severity.LOW})

    (out,) = config.apply(findings)

    assert out.severity is Severity.LOW
    # original object is not mutated
    assert findings[0].severity is Severity.HIGH


def test_explicit_config_path(tmp_path: Path) -> None:
    cfg = tmp_path / "custom.toml"
    cfg.write_text('fail_on = "never"\n', encoding="utf-8")

    config = load_config(tmp_path, explicit_path=cfg)

    assert config.fail_on == "never"
