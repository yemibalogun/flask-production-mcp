from mcp.server.fastmcp import FastMCP

from flask_production_mcp.tools.project import inspect_flask_project
from flask_production_mcp.tools.security import audit_security


mcp = FastMCP(
    "Flask Production MCP",
    instructions=(
        "Production engineering assistant for Flask applications. "
        "Use the available tools to inspect application structure, "
        "security, database configuration, performance, and production readiness."
    ),
)

mcp.tool()(inspect_flask_project)
mcp.tool()(audit_security)


if __name__ == "__main__":
    mcp.run()