"""Smoke tests for the MCP server wiring."""

from __future__ import annotations

import asyncio

from flask_production_mcp.server import mcp

EXPECTED_TOOLS = {
    "inspect_flask_project",
    "audit_flask",
    "audit_architecture",
    "audit_templates",
    "audit_security",
    "audit_database",
    "audit_dependencies",
    "audit_deployment",
    "audit_code_quality",
    "audit_flask_production",
}


def test_server_exposes_expected_tools() -> None:
    tools = asyncio.run(mcp.list_tools())
    names = {tool.name for tool in tools}

    assert EXPECTED_TOOLS.issubset(names)


def test_every_tool_has_a_description() -> None:
    tools = asyncio.run(mcp.list_tools())

    for tool in tools:
        assert tool.description, f"{tool.name} is missing a description"


def test_tool_call_roundtrip(tmp_path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n\napp = Flask(__name__)\n",
        encoding="utf-8",
    )

    result = asyncio.run(
        mcp.call_tool(
            "audit_flask_production",
            {"project_path": str(tmp_path)},
        )
    )

    # FastMCP returns (content, structured) or just content depending on
    # version; the structured payload is what matters here.
    payload = result[1] if isinstance(result, tuple) else result

    assert payload is not None
