"""Flask Production MCP package."""

from __future__ import annotations

import sys


def main() -> None:
    """Entry point: dispatch to the CLI (bare invocation starts the server)."""

    from flask_production_mcp.cli import main as cli_main

    raise SystemExit(cli_main(sys.argv[1:]))
