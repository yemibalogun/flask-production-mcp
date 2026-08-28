"""Flask Production MCP package."""

from __future__ import annotations

from flask_production_mcp.server import mcp


def main() -> None:
    """Start the Flask Production MCP server."""
    mcp.run()