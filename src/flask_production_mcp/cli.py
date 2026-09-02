"""Command-line interface for Flask Production MCP.

    flask-production-mcp audit [PATH] [options]   # run the unified audit
    flask-production-mcp serve                    # start the MCP server
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from flask_production_mcp.analyzers.production import analyze_production
from flask_production_mcp.config import load_config

_CATEGORY_ORDER = [
    "flask",
    "architecture",
    "templates",
    "deployment",
    "security",
    "database",
    "dependencies",
    "code_quality",
]


def _rel(path: str | None, root: Path) -> str:
    if not path:
        return "?"
    try:
        return str(Path(path).resolve().relative_to(root))
    except (ValueError, OSError):
        return path


def _print_text(result: dict[str, Any], root: Path, quiet: bool) -> None:
    score = result["overall_score"]
    ready = result["production_ready"]
    status = "READY" if ready else "NOT READY"

    print(f"Flask Production Audit  --  {result['project_path']}")
    print("-" * 60)
    print(f"Overall score  {score}/100          {status}")
    print()

    categories = result.get("categories", {})
    for name in _CATEGORY_ORDER:
        cat = categories.get(name)
        if not cat:
            continue
        count = cat["finding_count"]
        if name == "dependencies" and not cat.get("scanned", True):
            detail = "not scanned"
        elif count == 0:
            detail = "clean"
        else:
            detail = f"{count} finding{'s' if count != 1 else ''}"
            if cat["blocker_count"]:
                detail += f" ({cat['blocker_count']} blocker)"
        print(f"  {name:<14}{cat['score']:>4}   {detail}")
    print()

    _print_group("BLOCKERS", result.get("blockers", []), root, marker="x")
    if not quiet:
        _print_group(
            "ADVISORIES", result.get("advisories", []), root, marker="!"
        )
        _print_grouped_notes(result.get("notes", []))

    errors = result.get("errors", [])
    if errors:
        print(f"\n{len(errors)} note(s) during analysis:")
        for error in errors:
            print(f"  - {error}")

    print()
    if ready:
        print("Result: production ready")
    else:
        print("Result: NOT production ready")
        for reason in result.get("blocking_reasons", []):
            print(f"  - {reason}")


def _print_group(
    heading: str,
    findings: list[dict],
    root: Path,
    marker: str,
) -> None:
    if not findings:
        return
    print(f"{heading} ({len(findings)})")
    for finding in findings:
        loc = _rel(finding.get("file"), root)
        line = finding.get("line")
        where = f"{loc}:{line}" if line else loc
        print(
            f"  {marker} [{finding['id']}] {finding['category']}  {where}"
        )
        print(f"      {finding['title']}")
        rec = finding.get("recommendation")
        if rec:
            print(f"      -> {rec}")
    print()


def _print_grouped_notes(notes: list[dict]) -> None:
    if not notes:
        return
    counts = Counter((n["id"], n["title"]) for n in notes)
    print(f"NOTES ({len(notes)})")
    for (rule_id, title), count in counts.most_common():
        tag = f" x{count}" if count > 1 else ""
        print(f"  . [{rule_id}]{tag}  {title}")
    print()


def _print_github(result: dict[str, Any], root: Path) -> None:
    for finding in result.get("blockers", []):
        _emit_annotation("error", finding, root)
    for finding in result.get("advisories", []):
        _emit_annotation("warning", finding, root)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as handle:
                handle.write(_markdown_summary(result))
        except OSError:
            pass


def _emit_annotation(level: str, finding: dict, root: Path) -> None:
    loc = _rel(finding.get("file"), root)
    line = finding.get("line")
    parts = [f"file={loc}"]
    if line:
        parts.append(f"line={line}")
    title = f"{finding['id']}: {finding['title']}"
    message = finding.get("recommendation") or finding["title"]
    print(f"::{level} {','.join(parts)},title={title}::{message}")


def _markdown_summary(result: dict[str, Any]) -> str:
    lines = ["## Flask Production Audit", ""]
    status = (
        "production ready"
        if result["production_ready"]
        else "**NOT production ready**"
    )
    lines.append(f"Overall score **{result['overall_score']}/100** — {status}")
    lines.append("")
    lines.append("| Category | Score | Findings |")
    lines.append("| --- | --- | --- |")
    for name in _CATEGORY_ORDER:
        cat = result.get("categories", {}).get(name)
        if cat:
            lines.append(
                f"| {name} | {cat['score']} | {cat['finding_count']} |"
            )
    lines.append("")
    for reason in result.get("blocking_reasons", []):
        lines.append(f"- {reason}")
    lines.append("")
    return "\n".join(lines)


def _should_fail(result: dict[str, Any]) -> bool:
    return not result.get("production_ready", False)


def _cmd_audit(args: argparse.Namespace) -> int:
    project = Path(args.path).expanduser().resolve()
    if not project.is_dir():
        print(f"error: not a directory: {project}", file=sys.stderr)
        return 2

    config = load_config(project, explicit_path=args.config)
    if args.fail_on:
        config.fail_on = args.fail_on

    scan_dependencies = False if args.skip_deps else None
    run_bandit = False if args.skip_bandit else None

    try:
        result = analyze_production(
            project,
            scan_dependencies=scan_dependencies,
            run_bandit=run_bandit,
            config=config,
        )
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    elif args.github:
        _print_github(result, project)
    else:
        _print_text(result, project, quiet=args.quiet)

    return 1 if _should_fail(result) else 0


def _cmd_serve(_args: argparse.Namespace) -> int:
    from flask_production_mcp.server import mcp

    mcp.run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="flask-production-mcp",
        description="Static production-readiness audit for Flask apps.",
    )
    sub = parser.add_subparsers(dest="command")

    audit = sub.add_parser("audit", help="run the unified audit")
    audit.add_argument("path", nargs="?", default=".", help="project path")
    audit.add_argument(
        "--json", action="store_true", help="emit the full JSON result"
    )
    audit.add_argument(
        "--github",
        action="store_true",
        help="emit GitHub Actions annotations + job summary",
    )
    audit.add_argument(
        "--fail-on",
        choices=["blockers", "advisories", "any", "never"],
        help="override the fail_on policy",
    )
    audit.add_argument(
        "--skip-deps",
        action="store_true",
        help="skip the dependency CVE scan (no network)",
    )
    audit.add_argument(
        "--skip-bandit", action="store_true", help="skip the Bandit scan"
    )
    audit.add_argument("--config", help="path to a config TOML file")
    audit.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="print blockers only, not advisories/notes",
    )
    audit.set_defaults(func=_cmd_audit)

    serve = sub.add_parser("serve", help="start the MCP server (stdio)")
    serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    # Bare invocation (how MCP clients launch it) starts the server.
    if not argv:
        return _cmd_serve(argparse.Namespace())

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
