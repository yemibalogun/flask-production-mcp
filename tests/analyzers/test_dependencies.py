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
