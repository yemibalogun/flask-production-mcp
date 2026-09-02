"""Tests for the Bandit integration."""

from __future__ import annotations

from pathlib import Path

import flask_production_mcp.analyzers.bandit_scan as bandit_scan
from flask_production_mcp.analyzers.bandit_scan import bandit_findings
from flask_production_mcp.models.findings import (
    Confidence,
    Finding,
    Severity,
)


def _result(root: Path, line: int, test_id: str = "B307") -> dict:
    return {
        "filename": str(root / "app.py"),
        "line_number": line,
        "test_id": test_id,
        "test_name": "blacklist",
        "issue_severity": "MEDIUM",
        "issue_confidence": "HIGH",
        "issue_text": "Use of possibly insecure function eval.",
        "more_info": "https://bandit.example/B307",
        "issue_cwe": {"id": 78},
    }


def test_maps_bandit_result_to_finding(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    monkeypatch.setattr(
        bandit_scan,
        "run_bandit",
        lambda root, timeout=120: ([_result(tmp_path, 5)], None),
    )

    findings, errors = bandit_findings(tmp_path, existing=[])

    assert errors == []
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "SEC-BANDIT-B307"
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.HIGH
    assert finding.line == 5
    assert finding.metadata["source"] == "bandit"
    assert finding.metadata["cwe"] == 78


def test_dedupes_against_existing_findings(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    existing = [
        Finding(
            id="SEC-CODE-001",
            category="security",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="eval() detected",
            description="...",
            recommendation="...",
            file=str(tmp_path / "app.py"),
            line=5,
        )
    ]

    # Bandit reports the same issue one line off - still deduped (+/-1).
    monkeypatch.setattr(
        bandit_scan,
        "run_bandit",
        lambda root, timeout=120: ([_result(tmp_path, 6)], None),
    )

    findings, _ = bandit_findings(tmp_path, existing=existing)

    assert findings == []


def test_scan_error_is_reported_not_swallowed(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        bandit_scan,
        "run_bandit",
        lambda root, timeout=120: ([], "bandit is not installed"),
    )

    findings, errors = bandit_findings(tmp_path, existing=[])

    assert findings == []
    assert errors == ["Bandit scan skipped: bandit is not installed"]
