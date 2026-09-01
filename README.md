# Flask Production MCP

An [MCP](https://modelcontextprotocol.io) server that lets an AI coding agent
audit a Flask application for **production readiness** while you build it.

It answers the question *"is this Flask app ready to deploy?"* — not just
*"does it have security bugs?"* — across four areas:

| Area | What it checks |
| --- | --- |
| **Architecture** | application factory, blueprints, route inventory, duplicate routes, debug mode left enabled |
| **Security** | hardcoded secrets, `eval`/`exec`, `pickle` loads, missing auth on sensitive routes, missing rate limiting, debug config |
| **Database** | SQLAlchemy models / relationships / indexes, raw SQL, missing indexes on filtered columns, likely N+1 access |
| **Code quality** | bare `except`, broad `except Exception`, `print()`, `breakpoint()`, `assert` in app code, `TODO`/`FIXME` |

All analysis is **static** (AST based). The target application is never
imported or executed, and virtual-environments / caches / build dirs are
skipped.

## How it works

```
AI agent ──MCP──► Flask Production MCP ──► analyzers ──► Flask project files
                    (FastMCP server)        (AST)         (never executed)
```

## Tools

| Tool | Purpose |
| --- | --- |
| `audit_flask_production` | **Start here.** Runs every analyzer and returns one report with an overall score, per-category scores, `production_ready` + `blocking_reasons`, and findings split into `blockers` / `warnings` / `recommendations`. |
| `inspect_flask_project` | Structural discovery only: file counts, directories, blueprints, routes, framework indicators. |
| `audit_flask` | Architecture findings (debug mode, duplicate routes) with a score. |
| `audit_security` | Full security audit. |
| `audit_database` | Database architecture + performance findings, plus discovered models / queries / raw SQL. |
| `audit_code_quality` | Production code-quality findings (test modules are ignored). |

Every `audit_*` tool returns the same envelope:

```jsonc
{
  "success": true,
  "project_path": "/abs/path",
  "score": 82,                 // 0-100
  "summary": { "critical": 0, "high": 1, "medium": 3, "low": 4, "info": 2 },
  "findings": [ /* Finding objects: id, category, severity, confidence,
                   title, description, recommendation, file, line, metadata */ ],
  "recommendations": [ "…" ],
  "errors": [ "…" ]
}
```

`audit_flask_production` returns a superset (see `overall_score`,
`categories`, `production_ready`, `blocking_reasons`, `blockers`,
`warnings`, `recommendations`).

A project is reported `production_ready` only when it has **no critical or
high-severity findings** and its **overall score is ≥ 70**.

## Install

```bash
uv sync
```

## Run

```bash
uv run flask-production-mcp
```

The server speaks MCP over stdio.

### Register with an MCP client

Claude Code / Claude Desktop (`claude_desktop_config.json`):

```jsonc
{
  "mcpServers": {
    "flask-production": {
      "command": "uv",
      "args": ["run", "flask-production-mcp"],
      "cwd": "/path/to/flask-production-mcp"
    }
  }
}
```

Then ask the agent, e.g.:

> Run a production audit on `/path/to/my_flask_app` and list the blockers.

## Development

```bash
uv run pytest        # 100 tests
uv run ruff check src tests
uv run mypy src
```

Layout:

```
src/flask_production_mcp/
├── server.py            # FastMCP server, registers the tools
├── models/findings.py   # Finding / AuditSummary / AuditResult
├── analyzers/
│   ├── base.py          # scoring, summary, build_audit_result
│   ├── exclusions.py    # shared file-walk + exclusion rules
│   ├── flask.py         # discovery + analyze_flask
│   ├── security.py      # analyze_security
│   ├── database.py      # analyze_database
│   ├── code_quality.py  # analyze_code_quality_file
│   └── production.py    # analyze_production (unified)
└── tools/               # one thin MCP wrapper per analyzer
```

## Scope

Out of scope for now (possible future work): Docker/Nginx/Gunicorn config
analysis, dependency CVE scanning, performance profiling, test-coverage
analysis, and any dynamic/runtime testing.
