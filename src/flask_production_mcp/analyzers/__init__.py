"""Production-readiness analyzers for Flask Production MCP.

Scoring and summary helpers live in :mod:`flask_production_mcp.analyzers.base`
and are re-exported here so existing imports keep working.
"""

from __future__ import annotations

from flask_production_mcp.analyzers.base import (
    SEVERITY_PENALTIES,
    build_audit_result,
    build_summary,
    calculate_score,
    is_python_file,
    recommendations_from_findings,
)

__all__ = [
    "SEVERITY_PENALTIES",
    "build_audit_result",
    "build_summary",
    "calculate_score",
    "is_python_file",
    "recommendations_from_findings",
]
