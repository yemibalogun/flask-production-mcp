"""Manual tests for the hardcoded-secret detector."""

from __future__ import annotations

import ast
from pathlib import Path

from flask_production_mcp.analyzers.security import _find_hardcoded_secrets


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
        'FLUTTERWAVE_SECRET_KEY = "test_secret_key"\n'
        'FLUTTERWAVE_SECRET_HASH = "test_secret_hash"\n'
        'FLUTTERWAVE_PUBLIC_KEY = "test_public_key"',
        "Flutterwave test credentials",
        False,
    ),
)


def run_sample_tests() -> int:
    """Run synthetic detector tests and return the failure count."""

    failures = 0

    for source, description, should_detect in SAMPLES:
        try:
            tree = ast.parse(source)
            findings = _find_hardcoded_secrets(
                Path("test.py"),
                tree,
            )
        except (SyntaxError, OSError) as exc:
            print(f"ERROR: {description}: {exc}")
            failures += 1
            continue

        detected = bool(findings)

        status = "PASS" if detected == should_detect else "FAIL"

        print(
            f"{status}: {description} "
            f"(detected={detected}, expected={should_detect})"
        )

        if detected != should_detect:
            failures += 1

        for finding in findings:
            print(
                f"    {finding.id}: "
                f"{finding.metadata.get('variable')}"
            )

    return failures


def run_real_config_test() -> int:
    """
    Test the detector against the actual project's test configuration.

    The test deliberately checks only whether the known test credentials
    produce findings. It does not print their values.
    """

    config_path = Path(
        r"C:\Users\USER\Documents\Code_Projects\food_store\app\config.py"
    )

    if not config_path.is_file():
        print(f"ERROR: Config file does not exist: {config_path}")
        return 1

    try:
        source = config_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
        tree = ast.parse(
            source,
            filename=str(config_path),
        )
    except (OSError, SyntaxError) as exc:
        print(f"ERROR: Could not parse config.py: {exc}")
        return 1

    findings = _find_hardcoded_secrets(
        config_path,
        tree,
    )

    # These three values are deliberately test credentials and should
    # therefore NOT be classified as production hardcoded secrets.
    test_variables = {
        "FLUTTERWAVE_SECRET_KEY",
        "FLUTTERWAVE_SECRET_HASH",
    }

    false_positives = [
        finding
        for finding in findings
        if finding.metadata.get("variable") in test_variables
    ]

    if false_positives:
        print("FAIL: Test Flutterwave credentials were detected.")

        for finding in false_positives:
            print(
                f"    {finding.id}: "
                f"{finding.metadata.get('variable')}"
            )

        return 1

    print(
        "PASS: Actual config.py test Flutterwave credentials "
        "were correctly ignored."
    )

    return 0


def main() -> None:
    """Run all hardcoded-secret detector tests."""

    failures = 0

    print("Running synthetic detector tests...")
    failures += run_sample_tests()

    print("\nRunning real config.py test...")
    failures += run_real_config_test()

    if failures:
        raise SystemExit(
            f"\n{failures} test(s) failed."
        )

    print("\nAll secret-detector tests passed.")


if __name__ == "__main__":
    main()
