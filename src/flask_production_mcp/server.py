from mcp.server.fastmcp import FastMCP

from flask_production_mcp.tools.architecture import audit_architecture
from flask_production_mcp.tools.code_quality import audit_code_quality
from flask_production_mcp.tools.database import audit_database
from flask_production_mcp.tools.dependencies import audit_dependencies
from flask_production_mcp.tools.deployment import audit_deployment
from flask_production_mcp.tools.flask_audit import audit_flask
from flask_production_mcp.tools.production import audit_flask_production
from flask_production_mcp.tools.project import inspect_flask_project
from flask_production_mcp.tools.security import audit_security
from flask_production_mcp.tools.templates import audit_templates
from flask_production_mcp.tools.testing import audit_testing

mcp = FastMCP(
    "Flask Production MCP",
    instructions=(
        "Production engineering assistant for Flask applications. "
        "Use the available tools to inspect application structure, "
        "security, database configuration, code quality, and overall "
        "production readiness. Start with audit_flask_production for a "
        "complete assessment, or call an individual audit_* tool to focus "
        "on one area. All analysis is static; the target app is never run."
    ),
)

mcp.tool()(inspect_flask_project)
mcp.tool()(audit_flask)
mcp.tool()(audit_architecture)
mcp.tool()(audit_templates)
mcp.tool()(audit_security)
mcp.tool()(audit_database)
mcp.tool()(audit_dependencies)
mcp.tool()(audit_deployment)
mcp.tool()(audit_testing)
mcp.tool()(audit_code_quality)
mcp.tool()(audit_flask_production)


if __name__ == "__main__":
    mcp.run()
