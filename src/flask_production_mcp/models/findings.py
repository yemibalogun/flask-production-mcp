"""Data models used by the Flask Production MCP audit engine."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Severity assigned to an audit finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    """Confidence that a static-analysis finding represents a real issue."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Finding(BaseModel):
    """Represents one production-readiness finding."""

    id: str = Field(min_length=1)
    category: str = Field(min_length=1)

    severity: Severity
    confidence: Confidence = Confidence.MEDIUM

    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)

    file: str | None = None
    line: int | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditSummary(BaseModel):
    """Aggregated finding counts."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class AuditResult(BaseModel):
    """Complete result returned by an analyzer."""

    success: bool
    project_path: str

    score: int = Field(default=100, ge=0, le=100)

    findings: list[Finding] = Field(default_factory=list)

    summary: AuditSummary = Field(default_factory=AuditSummary)

    recommendations: list[str] = Field(default_factory=list)

    errors: list[str] = Field(default_factory=list)