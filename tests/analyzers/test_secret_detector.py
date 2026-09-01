"""Tests for the hardcoded-secret detector.

Ported from the standalone ``test_secret_detector.py`` script that used to
live at the repository root.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from flask_production_mcp.analyzers.security import _find_hardcoded_secrets

# (source, description, should_detect)
SAMPLES: tuple[tuple[str, str, bool], ...] = (
    (
        'SECRET_KEY = os.getenv("SECRET_KEY")',
        "environment variable",
        False,
    ),
    (
        'SECRET_KEY = "your-secret-key-here"',
        "placeholder secret",
        False,
    ),
    (
        'SECRET_KEY = "real-production-secret-123456"',
        "real SECRET_KEY",
        True,
    ),
    (
        'FLUTTERWAVE_SECRET_KEY = "real-flutterwave-secret-123456"',
        "real Flutterwave secret",
        True,
    ),
    (
        'FLUTTERWAVE_SECRET_HASH = "real-flutterwave-hash-123456"',
        "real Flutterwave hash",
        True,
    ),
    (
        (
            'FLUTTERWAVE_SECRET_KEY = "test_secret_key"\n'
            'FLUTTERWAVE_SECRET_HASH = "test_secret_hash"\n'
            'FLUTTERWAVE_PUBLIC_KEY = "test_public_key"'
        ),
        "Flutterwave test credentials",
        False,
    ),
)


@pytest.mark.parametrize(
    "source, description, should_detect",
    SAMPLES,
    ids=[sample[1] for sample in SAMPLES],
)
def test_hardcoded_secret_detection(
    source: str,
    description: str,
    should_detect: bool,
) -> None:
    tree = ast.parse(source)

    findings = _find_hardcoded_secrets(Path("config.py"), tree)

    assert bool(findings) is should_detect, description
