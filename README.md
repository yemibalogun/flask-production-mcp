# Flask Production MCP

A static **production-readiness auditor for Flask applications**, usable
three ways:

- a **CLI** (`flask-production-mcp audit`) for local runs and scripts
- a **pre-commit hook** and a **GitHub Action** so it runs at the right moments
- an **MCP server** so an AI coding agent can call it while building

It answers *"is this Flask app ready to deploy?"* — not just *"does it have
security bugs?"* — across six areas:

| Category | What it checks |
| --- | --- |
| **flask** | app-factory / blueprint discovery, route inventory, duplicate routes, debug mode enabled |
| **architecture** | extensions bound at import time, module-level `Flask()` beside a factory, hardcoded `SECRET_KEY` fallback, `db.create_all()` instead of migrations, unguarded `app.run()`, unregistered blueprints |
| **templates** | POST forms with no CSRF field, `\| safe` / `{% autoescape false %}` on dynamic data, `url_for()` to an endpoint that doesn't exist |
| **security** | `eval`/`exec`, `pickle` loads, hardcoded secrets, missing auth on sensitive routes, **missing rate limiting**, debug config — plus **Bandit**, folded in and de-duplicated |
| **database** | SQLAlchemy models / relationships / indexes, raw SQL, missing indexes on filtered columns, likely N+1 access |
| **dependencies** | known CVEs in `requirements*.txt`, via **pip-audit** (PyPI + OSV advisory databases) |
| **code_quality** | bare/broad `except`, `print()`, `breakpoint()`, `assert` in app code, `TODO`/`FIXME` (test modules excluded) |

All analysis is **static**. The target application is never imported or
executed; virtual-environments, caches and build dirs are skipped.

## Findings: blockers vs. advisories vs. notes

Every finding has a **severity** and a **confidence**. The audit sorts them:

| Tier | Rule | Gates a release? |
| --- | --- | --- |
| **blockers** | high-confidence critical/high | **yes** |
| **advisories** | other critical/high/medium — needs a judgement call | no (configurable) |
| **notes** | low / info cleanups | no |

The `overall_score` is **confidence-weighted**: a confirmed critical bites
hard, a long tail of "consider an index" guesses barely moves it. A project
is `production_ready` when it has **no blockers** and no single category has
collapsed below the score floor (default 50).

## Install

```bash
pip install flask-production-mcp
# or, from a checkout:
uv sync
```

Python 3.13+. `pip-audit` and `bandit` are installed as dependencies; the
CVE scan needs network access.

## CLI

```bash
flask-production-mcp audit path/to/your/flask/app
```

```
Flask Production Audit  --  /path/to/app
------------------------------------------------------------
Overall score  84/100          NOT READY

  flask          100   clean
  architecture    96   1 finding
  templates       55   1 finding (1 blocker)
  security       100   clean
  database        76   6 findings
  dependencies   100   clean
  code_quality    79   7 findings

BLOCKERS (1)
  x [TMPL-CSRF-001] templates  app/templates/admin/products.html:242
      POST form has no CSRF token field
      -> Add a hidden CSRF field inside the form ...

Result: NOT production ready
  - 1 blocker(s) in templates
```

| Flag | Effect |
| --- | --- |
| `--json` | emit the full JSON result |
| `--github` | emit GitHub Actions `::error` / `::warning` annotations + job summary |
| `--fail-on {blockers,advisories,any,never}` | what makes exit code 1 |
| `--skip-deps` | skip the CVE scan (no network) |
| `--skip-bandit` | skip the Bandit scan |
| `--config FILE` | use a specific config TOML |
| `-q` | print blockers only |

Exit codes: `0` pass · `1` fail (per `--fail-on`) · `2` bad usage.

## Configuration

`flask-production.toml` in the project root, or `[tool.flask-production]`
in `pyproject.toml`. See [`flask-production.toml.example`](flask-production.toml.example).

```toml
fail_on = "blockers"
category_floor = 50
scan_dependencies = true
run_bandit = true
ignore = ["DB-PERF-001"]        # drop rules by id
select = []                      # if set, run ONLY these

[severity]
"ARCH-SEC-001" = "high"          # re-grade a rule for this project
```

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/<owner>/flask-production-mcp
    rev: v0.1.0
    hooks:
      - id: flask-production-audit
```

The hook runs offline (`--skip-deps --skip-bandit -q`) and fails the commit
on **blockers only**. Override `args:` to change that.

## GitHub Action

```yaml
# .github/workflows/audit.yml
jobs:
  flask-production-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: <owner>/flask-production-mcp@v0.1.0
        with:
          path: .
          fail-on: blockers      # or advisories / any / never
```

Findings appear as inline annotations on the PR and in the job summary.

## MCP server

```bash
flask-production-mcp serve      # stdio
```

Register with an MCP client (Claude Code / Desktop):

```jsonc
{
  "mcpServers": {
    "flask-production": {
      "command": "flask-production-mcp",
      "args": ["serve"]
    }
  }
}
```

Then: *"Run a production audit on /path/to/my_flask_app and list the blockers."*

### Tools

| Tool | Purpose |
| --- | --- |
| `audit_flask_production` | **Start here.** Unified audit: `overall_score`, per-category `score`, `production_ready` + `blocking_reasons`, `blockers` / `advisories` / `notes`. |
| `inspect_flask_project` | Structure only: file counts, blueprints, routes, indicators. |
| `audit_flask` | Flask route/debug findings. |
| `audit_architecture` | Flask-architecture rules. |
| `audit_templates` | Jinja/HTML template findings. |
| `audit_security` | Security audit (incl. Bandit). |
| `audit_database` | Database architecture + performance findings. |
| `audit_dependencies` | Dependency CVE scan. |
| `audit_code_quality` | Production code-quality findings. |

Every `audit_*` tool returns the same envelope (`success`, `project_path`,
`score`, `summary`, `findings`, `recommendations`, `errors`).

## Development

```bash
uv run pytest
uv run ruff check src tests
uv run mypy src
```

```
src/flask_production_mcp/
├── cli.py                  # audit / serve subcommands
├── config.py               # flask-production.toml loader + finding policy
├── server.py               # MCP server, registers the tools
├── models/findings.py      # Finding / AuditSummary / AuditResult
├── analyzers/
│   ├── base.py             # scoring (weighted), classification
│   ├── exclusions.py       # shared file-walk + exclusion rules
│   ├── flask.py            # discovery + analyze_flask
│   ├── architecture.py     # Flask-architecture rules
│   ├── templates.py        # Jinja/HTML rules
│   ├── security.py         # analyze_security
│   ├── bandit_scan.py      # Bandit integration
│   ├── database.py         # analyze_database
│   ├── dependencies.py     # pip-audit integration
│   ├── code_quality.py     # analyze_code_quality_file
│   └── production.py       # analyze_production (unified)
└── tools/                  # one thin MCP wrapper per analyzer
```

## Scope

Not covered yet: Docker/Nginx/Gunicorn config, `pyproject.toml`/lock-file
dependency scanning (only `requirements*.txt`), performance profiling,
test-coverage analysis, and any dynamic/runtime testing.
