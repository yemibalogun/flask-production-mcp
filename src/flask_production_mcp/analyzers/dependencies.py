"""Dependency vulnerability scanning.

This analyzer shells out to ``pip-audit`` (which queries the PyPI and OSV
advisory databases) rather than reimplementing a shallow CVE checker. It
degrades gracefully when pip-audit is missing or the advisory database is
unreachable - a scan that cannot run is reported as an error, never a
crash and never a false "all clear".
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.exclusions import should_exclude_path
from flask_production_mcp.models.findings import (
    Confidence,
    Finding,
    Severity,
)

_DEFAULT_TIMEOUT = 120

_REQUIREMENTS_GLOBS = ("requirements*.txt", "requirements/*.txt")


def _find_requirements_files(root: Path) -> list[Path]:
    seen: set[Path] = set()
    found: list[Path] = []

    for pattern in _REQUIREMENTS_GLOBS:
        for path in root.glob(pattern):
            if not path.is_file():
                continue
            if path.suffix != ".txt":
                continue
            if path.name.endswith(".backup"):
                continue
            if should_exclude_path(path, root):
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            found.append(path)

    return sorted(found)


_LOCK_FILES = ("uv.lock", "poetry.lock", "Pipfile.lock")


def _packages_from_lockfile(lock_path: Path) -> list[tuple[str, str]] | None:
    """Extract (name, version) pairs from a lock file, or None if unreadable."""

    name = lock_path.name.lower()
    try:
        if name in {"uv.lock", "poetry.lock"}:
            with lock_path.open("rb") as handle:
                data = tomllib.load(handle)
            packages = data.get("package", [])
            pairs = [
                (str(p["name"]), str(p["version"]))
                for p in packages
                if isinstance(p, dict) and p.get("name") and p.get("version")
            ]
            return pairs or None
        if name == "pipfile.lock":
            data = json.loads(lock_path.read_text(encoding="utf-8"))
            pairs = []
            for section in ("default", "develop"):
                for pkg, meta in (data.get(section) or {}).items():
                    version = str(meta.get("version", "")).lstrip("=")
                    if version:
                        pairs.append((pkg, version))
            return pairs or None
    except (OSError, tomllib.TOMLDecodeError, json.JSONDecodeError, KeyError):
        return None
    return None


def _scan_target(
    scan_input: Path,
    report_as: Path,
    root: Path,
    timeout: int,
) -> tuple[list[Finding], str | None]:
    report, error = _run_pip_audit(scan_input, root, timeout)
    if error is not None:
        return [], error
    return _findings_for_manifest(report_as, report or {}), None


def _scan_pairs(
    pairs: list[tuple[str, str]],
    report_as: Path,
    root: Path,
    timeout: int,
) -> tuple[list[Finding], str | None]:
    """Write ``name==version`` pairs to a temp file and scan it."""

    with tempfile.NamedTemporaryFile(
        "w", suffix=".txt", delete=False, encoding="utf-8"
    ) as handle:
        handle.write("\n".join(f"{n}=={v}" for n, v in pairs))
        temp_path = Path(handle.name)
    try:
        return _scan_target(temp_path, report_as, root, timeout)
    finally:
        temp_path.unlink(missing_ok=True)


_SPECIFIER = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]+\])?\s*===?\s*"
    r"([A-Za-z0-9][A-Za-z0-9._-]*)"
)


def _pins_from_pyproject(
    pyproject: Path,
) -> tuple[list[tuple[str, str]], int]:
    """Return (exactly-pinned (name, version) pairs, count of unpinned)."""

    try:
        with pyproject.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return [], 0

    project = data.get("project", {})
    specs: list[str] = list(project.get("dependencies", []))
    for group in (project.get("optional-dependencies", {}) or {}).values():
        if isinstance(group, list):
            specs.extend(group)

    pinned: list[tuple[str, str]] = []
    unpinned = 0
    for spec in specs:
        if not isinstance(spec, str):
            continue
        match = _SPECIFIER.match(spec)
        if match:
            pinned.append((match.group(1), match.group(2)))
        else:
            unpinned += 1
    return pinned, unpinned


def _locate_package_line(manifest: Path, package: str) -> int | None:
    try:
        lines = manifest.read_text(
            encoding="utf-8-sig", errors="replace"
        ).splitlines()
    except OSError:
        return None

    needle = package.lower().replace("_", "-")
    for number, line in enumerate(lines, start=1):
        stripped = line.strip().lower().replace("_", "-")
        if stripped.startswith(needle) and (
            len(stripped) == len(needle)
            or not (stripped[len(needle)].isalnum())
        ):
            return number
    return None


def _run_pip_audit(
    manifest: Path,
    root: Path,
    timeout: int,
) -> tuple[dict[str, Any] | None, str | None]:
    """Return (parsed_json, error_message)."""

    command = [
        sys.executable,
        "-m",
        "pip_audit",
        "--requirement",
        str(manifest),
        "--format",
        "json",
        "--progress-spinner",
        "off",
    ]

    try:
        completed = subprocess.run(
            command,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return None, "pip-audit is not installed"
    except subprocess.TimeoutExpired:
        return None, (
            f"pip-audit timed out after {timeout}s for {manifest.name}"
        )

    stdout = (completed.stdout or "").strip()

    if not stdout:
        detail = (completed.stderr or "").strip().splitlines()
        tail = detail[-1] if detail else f"exit code {completed.returncode}"
        return None, f"pip-audit produced no output for {manifest.name}: {tail}"

    try:
        return json.loads(stdout), None
    except json.JSONDecodeError:
        # pip-audit exits 1 when vulns are found; that still yields JSON.
        # Reaching here means genuinely broken output.
        detail = (completed.stderr or "").strip().splitlines()
        tail = detail[-1] if detail else "unparseable output"
        return None, f"pip-audit output for {manifest.name} was not JSON: {tail}"


def _dependencies_from_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    # Current pip-audit: {"dependencies": [...]}. Older: a bare list.
    if isinstance(report, list):
        return [d for d in report if isinstance(d, dict)]
    deps = report.get("dependencies", [])
    return [d for d in deps if isinstance(d, dict)]


def _best_fix_version(fix_versions: list[str]) -> str | None:
    """Pick the highest fix version using a loose numeric comparison."""

    def key(value: str) -> tuple[int, ...]:
        parts: list[int] = []
        for chunk in value.split("."):
            digits = "".join(c for c in chunk if c.isdigit())
            parts.append(int(digits) if digits else 0)
        return tuple(parts)

    return max(fix_versions, key=key) if fix_versions else None


def _findings_for_manifest(
    manifest: Path,
    report: dict[str, Any],
) -> list[Finding]:
    """One finding per vulnerable package (not per CVE) to keep it actionable."""

    findings: list[Finding] = []

    for dependency in _dependencies_from_report(report):
        name = dependency.get("name", "?")
        version = dependency.get("version", "?")
        raw_vulns = [v for v in (dependency.get("vulns") or []) if isinstance(v, dict)]
        if not raw_vulns:
            continue

        vuln_ids = [str(v.get("id", "unknown")) for v in raw_vulns]
        all_fixes: list[str] = []
        for vuln in raw_vulns:
            all_fixes.extend(
                v for v in vuln.get("fix_versions", []) if isinstance(v, str)
            )
        target = _best_fix_version(all_fixes)

        line = _locate_package_line(manifest, str(name))
        in_manifest = line is not None
        count = len(raw_vulns)

        if target:
            recommendation = (
                f"Upgrade {name} to {target} or later"
                + (
                    ""
                    if in_manifest
                    else f" (pulled in transitively; pin it in {manifest.name} "
                    "or upgrade the package that requires it)"
                )
                + ", then run the test suite."
            )
        else:
            recommendation = (
                f"No fixed version of {name} is published. Track the "
                "advisories and mitigate at the application layer if the "
                "vulnerable code path is reachable."
            )

        first_desc = (raw_vulns[0].get("description") or "").strip()

        findings.append(
            Finding(
                id="DEP-VULN-001",
                category="dependencies",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                title=(
                    f"{name} {version}: {count} known "
                    f"vulnerabilit{'y' if count == 1 else 'ies'}"
                ),
                description=(
                    f"{name}=={version} is affected by {count} advisory"
                    f"{'' if count == 1 else 'ies'} "
                    f"({', '.join(vuln_ids[:6])}"
                    f"{', ...' if count > 6 else ''}). "
                    + (first_desc[:240] if first_desc else "")
                ).strip(),
                recommendation=recommendation,
                file=str(manifest),
                line=line,
                metadata={
                    "package": name,
                    "installed_version": version,
                    "vulnerability_ids": vuln_ids,
                    "vulnerability_count": count,
                    "recommended_version": target,
                    "in_manifest": in_manifest,
                    "manifest": manifest.name,
                },
            )
        )

    return findings


def analyze_dependencies(
    project_path: str | Path,
    timeout: int = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Scan a project's ``requirements*.txt`` files for known vulnerabilities.

    Returns ``{findings, errors, manifests, scanned}``. ``scanned`` is
    False when no scan could run (no manifest, tool missing, or the
    advisory database was unreachable) so callers can tell "clean" from
    "not checked".
    """

    root = Path(project_path).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError(f"Dependency analysis root is invalid: {root}")

    manifests = _find_requirements_files(root)
    lockfiles = [root / name for name in _LOCK_FILES if (root / name).is_file()]
    pyproject = root / "pyproject.toml"
    errors: list[str] = []
    findings: list[Finding] = []
    scanned_names: list[str] = []
    scanned_any = False

    if not manifests and not lockfiles and not pyproject.is_file():
        return {
            "findings": [],
            "errors": [
                "No requirements*.txt, lock file (uv.lock / poetry.lock / "
                "Pipfile.lock) or pyproject.toml found; dependency "
                "scanning was skipped."
            ],
            "manifests": [],
            "scanned": False,
        }

    for manifest in manifests:
        extra, error = _scan_target(manifest, manifest, root, timeout)
        scanned_names.append(manifest.name)
        if error is not None:
            errors.append(error)
            continue
        scanned_any = True
        findings.extend(extra)

    # Lock files and pyproject only add value where nothing is already
    # pinned in a requirements file for that project.
    if not manifests:
        for lock_path in lockfiles:
            pairs = _packages_from_lockfile(lock_path)
            if not pairs:
                errors.append(f"Could not parse {lock_path.name}")
                continue
            extra, error = _scan_pairs(pairs, lock_path, root, timeout)
            scanned_names.append(lock_path.name)
            if error is not None:
                errors.append(error)
                continue
            scanned_any = True
            findings.extend(extra)

    if not manifests and not lockfiles and pyproject.is_file():
        pinned, unpinned = _pins_from_pyproject(pyproject)
        if pinned:
            extra, error = _scan_pairs(pinned, pyproject, root, timeout)
            scanned_names.append(pyproject.name)
            if error is not None:
                errors.append(error)
            else:
                scanned_any = True
                findings.extend(extra)
        if unpinned:
            errors.append(
                f"{unpinned} dependenc"
                f"{'y' if unpinned == 1 else 'ies'} in pyproject.toml "
                "are not pinned to an exact version and could not be "
                "checked. Add a lock file (uv lock / poetry lock) for "
                "full coverage."
            )
        elif not pinned:
            errors.append(
                "pyproject.toml has no pinned dependencies to scan; add a "
                "lock file for dependency vulnerability coverage."
            )

    return {
        "findings": findings,
        "errors": errors,
        "manifests": scanned_names,
        "scanned": scanned_any,
    }
