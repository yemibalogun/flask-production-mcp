"""Project configuration for Flask Production MCP.

Configuration is read from (first match wins):

1. a path passed explicitly (``--config``)
2. ``flask-production.toml`` in the project root
3. ``[tool.flask-production]`` in ``pyproject.toml``
4. built-in defaults

Recognised keys::

    fail_on        = "blockers" | "advisories" | "any" | "never"
    category_floor = 50
    scan_dependencies = true
    run_bandit        = true
    ignore = ["DB-PERF-001", "CQ-CODE-002"]   # drop these rule ids
    select = ["TMPL-CSRF-001"]                # keep ONLY these (if set)

    [severity]                                # per-rule severity override
    "TMPL-SAFE-001" = "medium"
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from flask_production_mcp.models.findings import Finding, Severity

_VALID_FAIL_ON = {"blockers", "advisories", "any", "never"}
_DEFAULT_FLOOR = 50


@dataclass
class Config:
    """Resolved configuration for an audit run."""

    fail_on: str = "blockers"
    category_floor: int = _DEFAULT_FLOOR
    scan_dependencies: bool = True
    run_bandit: bool = True
    ignore: frozenset[str] = frozenset()
    select: frozenset[str] = frozenset()
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    source: str | None = None

    # ------------------------------------------------------------------
    # Finding post-processing
    # ------------------------------------------------------------------

    def applies_to(self, finding: Finding) -> bool:
        if self.select:
            return finding.id in self.select
        return finding.id not in self.ignore

    def apply(self, findings: list[Finding]) -> list[Finding]:
        """Filter by select/ignore and apply severity overrides."""

        kept: list[Finding] = []
        for finding in findings:
            if not self.applies_to(finding):
                continue
            override = self.severity_overrides.get(finding.id)
            if override is not None and override != finding.severity:
                finding = finding.model_copy(update={"severity": override})
            kept.append(finding)
        return kept


def _coerce_severity(value: object) -> Severity | None:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return None


def _config_from_mapping(data: dict, source: str) -> Config:
    config = Config(source=source)

    fail_on = str(data.get("fail_on", config.fail_on)).lower()
    if fail_on in _VALID_FAIL_ON:
        config.fail_on = fail_on

    floor = data.get("category_floor", config.category_floor)
    if isinstance(floor, int) and 0 <= floor <= 100:
        config.category_floor = floor

    if isinstance(data.get("scan_dependencies"), bool):
        config.scan_dependencies = data["scan_dependencies"]
    if isinstance(data.get("run_bandit"), bool):
        config.run_bandit = data["run_bandit"]

    ignore = data.get("ignore", [])
    if isinstance(ignore, list):
        config.ignore = frozenset(str(x) for x in ignore)

    select = data.get("select", [])
    if isinstance(select, list):
        config.select = frozenset(str(x) for x in select)

    severity = data.get("severity", {})
    if isinstance(severity, dict):
        overrides: dict[str, Severity] = {}
        for rule_id, raw in severity.items():
            coerced = _coerce_severity(raw)
            if coerced is not None:
                overrides[str(rule_id)] = coerced
        config.severity_overrides = overrides

    return config


def _read_toml(path: Path) -> dict | None:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None


def load_config(
    project_root: str | Path,
    explicit_path: str | Path | None = None,
) -> Config:
    """Resolve configuration for ``project_root``."""

    root = Path(project_root).expanduser().resolve()

    if explicit_path is not None:
        data = _read_toml(Path(explicit_path).expanduser())
        if data is not None:
            # An explicit file may still nest under [tool.flask-production].
            section = data.get("tool", {}).get("flask-production", data)
            return _config_from_mapping(section, str(explicit_path))
        return Config(source=None)

    dedicated = root / "flask-production.toml"
    if dedicated.is_file():
        data = _read_toml(dedicated)
        if data is not None:
            section = data.get("tool", {}).get("flask-production", data)
            return _config_from_mapping(section, str(dedicated))

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        data = _read_toml(pyproject)
        if data is not None:
            section = data.get("tool", {}).get("flask-production")
            if isinstance(section, dict):
                return _config_from_mapping(section, str(pyproject))

    return Config()
