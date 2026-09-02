"""Tests for the dependency (CVE) analyzer.

These do not touch the network: pip-audit is stubbed and the JSON parsing
helpers are tested directly.
"""

from __future__ import annotations

from pathlib import Path

import flask_production_mcp.analyzers.dependencies as deps
from flask_production_mcp.analyzers.dependencies import (
    _best_fix_version,
    _findings_for_manifest,
    _locate_package_line,
    _packages_from_lockfile,
    _pins_from_pyproject,
    analyze_dependencies,
)

_SAMPLE_REPORT = {
    "dependencies": [
        {"name": "flask", "version": "3.1.3", "vulns": []},
        {
            "name": "requests",
            "version": "2.19.1",
            "vulns": [
                {
                    "id": "PYSEC-2023-74",
                    "fix_versions": ["2.31.0"],
                    "aliases": ["CVE-2023-32681"],
                    "description": "Requests leaks Proxy-Authorization headers.",
                },
                {
                    "id": "PYSEC-2018-28",
                    "fix_versions": ["2.20.0"],
                    "aliases": [],
                    "description": "",
                },
            ],
        },
        {
            "name": "idna",
            "version": "2.7",
            "vulns": [
                {"id": "PYSEC-2024-60", "fix_versions": ["3.7"], "aliases": []}
            ],
        },
    ]
}


def test_best_fix_version_picks_highest() -> None:
    assert _best_fix_version(["2.20.0", "2.31.0", "2.9.1"]) == "2.31.0"
    assert _best_fix_version(["1.26.18", "2.0.7"]) == "2.0.7"
    assert _best_fix_version([]) is None


def test_locate_package_line(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "flask==3.1.3\nrequests==2.19.1\nFlask-Login==0.6.3\n",
        encoding="utf-8",
    )

    assert _locate_package_line(manifest, "requests") == 2
    assert _locate_package_line(manifest, "flask-login") == 3
    assert _locate_package_line(manifest, "gunicorn") is None


def test_findings_for_manifest_groups_by_package(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "flask==3.1.3\nrequests==2.19.1\n", encoding="utf-8"
    )

    findings = _findings_for_manifest(manifest, _SAMPLE_REPORT)

    # One finding per vulnerable package (requests, idna) - not per CVE.
    assert len(findings) == 2
    by_pkg = {f.metadata["package"]: f for f in findings}

    requests_finding = by_pkg["requests"]
    assert requests_finding.metadata["vulnerability_count"] == 2
    assert requests_finding.metadata["recommended_version"] == "2.31.0"
    assert requests_finding.metadata["in_manifest"] is True
    assert requests_finding.line == 2
    assert "2.31.0" in requests_finding.recommendation

    idna_finding = by_pkg["idna"]
    assert idna_finding.metadata["in_manifest"] is False
    assert idna_finding.line is None
    assert "transitively" in idna_finding.recommendation


def test_analyze_dependencies_no_manifest(tmp_path: Path) -> None:
    result = analyze_dependencies(tmp_path)

    assert result["scanned"] is False
    assert result["findings"] == []
    assert result["manifests"] == []
    assert result["errors"]


def test_analyze_dependencies_stubbed_scan(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "requirements.txt").write_text(
        "requests==2.19.1\n", encoding="utf-8"
    )

    def fake_run(manifest, root, timeout):
        return _SAMPLE_REPORT, None

    monkeypatch.setattr(deps, "_run_pip_audit", fake_run)

    result = analyze_dependencies(tmp_path)

    assert result["scanned"] is True
    assert result["manifests"] == ["requirements.txt"]
    assert {f.metadata["package"] for f in result["findings"]} == {
        "requests",
        "idna",
    }


def test_analyze_dependencies_scan_error_is_not_clean(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "requirements.txt").write_text(
        "requests==2.19.1\n", encoding="utf-8"
    )

    monkeypatch.setattr(
        deps,
        "_run_pip_audit",
        lambda m, r, t: (None, "advisory database unreachable"),
    )

    result = analyze_dependencies(tmp_path)

    assert result["scanned"] is False
    assert result["findings"] == []
    assert "advisory database unreachable" in result["errors"]


def test_packages_from_uv_lock(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "flask"\nversion = "3.1.3"\n\n'
        '[[package]]\nname = "requests"\nversion = "2.19.1"\n',
        encoding="utf-8",
    )

    pairs = _packages_from_lockfile(tmp_path / "uv.lock")

    assert ("flask", "3.1.3") in pairs
    assert ("requests", "2.19.1") in pairs


def test_packages_from_pipfile_lock(tmp_path: Path) -> None:
    (tmp_path / "Pipfile.lock").write_text(
        '{"default": {"requests": {"version": "==2.19.1"}}, '
        '"develop": {"pytest": {"version": "==9.1.1"}}}',
        encoding="utf-8",
    )

    pairs = dict(_packages_from_lockfile(tmp_path / "Pipfile.lock"))

    assert pairs["requests"] == "2.19.1"
    assert pairs["pytest"] == "9.1.1"


def test_analyze_dependencies_scans_lockfile_when_no_requirements(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.19.1"\n',
        encoding="utf-8",
    )

    captured: dict[str, Path] = {}

    def fake_run(scan_input, root, timeout):
        captured["input"] = scan_input
        return _SAMPLE_REPORT, None

    monkeypatch.setattr(deps, "_run_pip_audit", fake_run)

    result = analyze_dependencies(tmp_path)

    assert result["scanned"] is True
    assert result["manifests"] == ["uv.lock"]
    # pip-audit was fed a generated requirements file, not the lock itself.
    assert captured["input"].suffix == ".txt"
    assert {f.metadata["package"] for f in result["findings"]} == {
        "requests",
        "idna",
    }


def test_pins_from_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'name = "x"\n'
        'dependencies = ["flask==3.1.3", "requests>=2", "jinja2"]\n'
        "[project.optional-dependencies]\n"
        'dev = ["pytest==9.1.1"]\n',
        encoding="utf-8",
    )

    pinned, unpinned = _pins_from_pyproject(tmp_path / "pyproject.toml")

    assert dict(pinned) == {"flask": "3.1.3", "pytest": "9.1.1"}
    assert unpinned == 2


def test_analyze_dependencies_scans_pyproject_pins(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'name = "x"\n'
        'dependencies = ["requests==2.19.1", "jinja2"]\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        deps, "_run_pip_audit", lambda i, r, t: (_SAMPLE_REPORT, None)
    )

    result = analyze_dependencies(tmp_path)

    assert result["scanned"] is True
    assert result["manifests"] == ["pyproject.toml"]
    assert {f.metadata["package"] for f in result["findings"]} == {
        "requests",
        "idna",
    }
    # the unpinned jinja2 is surfaced as a coverage-gap note
    assert any("not pinned" in e for e in result["errors"])


def test_requirements_file_takes_precedence_over_pyproject(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "requirements.txt").write_text(
        "flask==3.1.3\n", encoding="utf-8"
    )
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["requests==2.19.1"]\n',
        encoding="utf-8",
    )

    seen: list[str] = []
    monkeypatch.setattr(
        deps,
        "_run_pip_audit",
        lambda i, r, t: (seen.append(i.name) or ({"dependencies": []}, None)),
    )

    result = analyze_dependencies(tmp_path)

    assert result["manifests"] == ["requirements.txt"]


def test_backup_requirements_are_ignored(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (tmp_path / "requirements.txt.backup").write_text(
        "flask\n", encoding="utf-8"
    )

    seen: list[str] = []

    def fake_run(manifest, root, timeout):
        seen.append(manifest.name)
        return {"dependencies": []}, None

    monkeypatch.setattr(deps, "_run_pip_audit", fake_run)
    analyze_dependencies(tmp_path)

    assert seen == ["requirements.txt"]
