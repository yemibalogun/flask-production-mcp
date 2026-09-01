flask-production-mcp/
│
├── src/
│   └── flask_production_mcp/
│       │
│       ├── server.py
│       ├── config.py
│       │
│       ├── tools/
│       │   ├── project_inspector.py
│       │   ├── security_audit.py
│       │   ├── database_audit.py
│       │   ├── flask_audit.py
│       │   ├── dependency_audit.py
│       │   └── deployment_audit.py
│       │
│       ├── analyzers/
│       │   ├── flask.py
│       │   ├── database.py
│       │   ├── security.py
│       │   └── dependencies.py
│       │
│       └── models/
│           ├── findings.py
│           └── project.py
│
├── tests/
│   ├── test_project_inspector.py
│   ├── test_security_audit.py
│   └── test_database_audit.py
│
├── pyproject.toml
└── README.md



✓ Flask configuration
✓ Secret management
✓ Authentication
✓ OAuth
✓ 2FA / TOTP
✓ OTP
✓ Password security
✓ Session security
✓ CSRF
✓ CORS
✓ Security headers
✓ Rate limiting
✓ SQLAlchemy configuration
✓ PostgreSQL indexes
✓ Connection pooling
✓ N+1 queries
✓ Database migrations
✓ Docker configuration
✓ Gunicorn
✓ Nginx
✓ HTTPS
✓ Dependency vulnerabilities
✓ Logging
✓ Error handling
✓ Production configuration


                    ┌──────────────────────┐
                    │  Claude / Cursor /   │
                    │  Your Build Tool     │
                    └──────────┬───────────┘
                               │
                               │ MCP
                               ▼
                    ┌──────────────────────┐
                    │ Flask Production MCP │
                    │       FastMCP         │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
       Project Inspector   Security Audit   DB Audit
              │                │                │
              └────────────────┼────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │ Flask Project Files  │
                    │ PostgreSQL Config    │
                    │ Docker / Nginx       │
                    └──────────────────────┘

DatabaseAnalysis
│
├── models
│   ├── columns
│   ├── relationships
│   ├── constraints
│   └── indexes
│
├── queries
│   ├── filters
│   ├── joins
│   ├── ordering
│   ├── pagination
│   └── raw_sql
│
└── configuration
    ├── database URI
    ├── pooling
    ├── timeout
    └── migration configuration


input validation
secure session cookies
hashed passwords
rate limit login and api
bot protection
database queries
escape user-generated content
restrict file uploads
trim API responses
security headers
https
scan dependencies andthe full app for vulnerabilities


| Intended feature           | Current analyzer           | Status     |
| -------------------------- | -------------------------- | ---------- |
| Flask configuration        | `flask.py`                 | 🟢 Covered |
| Secret management          | `security.py`              | 🟢 Covered |
| Authentication             | `security.py`              | 🟢 Covered |
| OAuth                      | `security.py`              | 🟢 Covered |
| 2FA / TOTP                 | `security.py`              | 🟢 Covered |
| OTP                        | `security.py`              | 🟢 Covered |
| Password security          | `security.py`              | 🟢 Covered |
| Session security           | `security.py`              | 🟢 Covered |
| CSRF                       | `security.py`              | 🟢 Covered |
| CORS                       | `security.py`              | 🟢 Covered |
| Security headers           | `security.py`              | 🟢 Covered |
| Rate limiting              | `security.py`              | 🟢 Covered |
| SQLAlchemy configuration   | `database.py`              | 🟢 Covered |
| PostgreSQL indexes         | `database.py`              | 🟢 Covered |
| Connection pooling         | `database.py`              | 🟢 Covered |
| N+1 queries                | `database.py`              | 🟢 Covered |
------------------------------------------------------------------------
| Database migrations        | `database.py`              | 🟡 Partial |
| Docker configuration       | `flask.py`                 | 🟡 Partial |
| Gunicorn                   | `flask.py`                 | 🟡 Partial |
| Nginx                      | `flask.py`                 | 🟡 Partial |
| HTTPS                      | `security.py` / `flask.py` | 🟡 Partial |
| Dependency vulnerabilities | `code_quality.py`          | 🟡 Partial |
| Logging                    | `code_quality.py`          | 🟡 Partial |
| Error handling             | `code_quality.py`          | 🟡 Partial |
| Production configuration   | `flask.py`                 | 🟡 Partial |



Flask Analyzer
│
├── 1. Project/app discovery
├── 2. Application factory detection
├── 3. Blueprint detection
├── 4. Route inventory
├── 5. HTTP method analysis
├── 6. Route authentication coverage
├── 7. Authorization coverage
├── 8. Error handlers
├── 9. Flask configuration
├── 10. Production/debug configuration
├── 11. Docker detection
├── 12. Gunicorn detection
├── 13. Nginx/reverse-proxy detection
└── 14. HTTPS/proxy configuration


✅ Security Analyzer
✅ Database Analyzer
🟢 Flask Analyzer       ← NEXT
⬜ Code Quality Analyzer refinement
⬜ Dependency Analyzer
⬜ Deployment Analyzer
⬜ Performance Analyzer
⬜ Testing Analyzer
⬜ Cross-file intelligence
⬜ Production readiness/scoring engine
⬜ CLI/reporting/CI


| Priority | Flask capability              | What we should detect                                               |
| -------- | ----------------------------- | ------------------------------------------------------------------- |
| **1**    | Application factory           | `create_app()` pattern, factory configuration problems              |
| **2**    | Blueprint architecture        | Blueprint definitions, registration, duplicate/missing registration |
| **3**    | Route quality                 | missing methods, unsafe route patterns, duplicate routes            |
| **4**    | Request lifecycle             | problematic `before_request`, `after_request`, `teardown` usage     |
| **5**    | App context                   | database/app-context misuse and potentially unsafe global state     |
| **6**    | Flask extensions              | initialization patterns and extensions initialized incorrectly      |
| **7**    | Jinja/template usage          | unsafe rendering patterns, template misuse                          |
| **8**    | Static/file serving           | dangerous custom file-serving patterns                              |
| **9**    | Response handling             | inconsistent/unsafe response construction                           |
| **10**   | Flask async usage             | problematic async route patterns                                    |
| **11**   | Global mutable state          | request-specific state stored globally                              |
| **12**   | Flask production architecture | development-server/debug patterns that belong specifically to Flask |


------------Recommended analyzer roadmap---------------------------
flask.py
    └── Flask architecture + configuration + application patterns

database.py
    └── SQLAlchemy + PostgreSQL + query performance

security.py
    └── Security/authentication hardening

code_quality.py
    └── General code quality + error handling + logging

deployment.py       ← NEW
    ├── Docker
    ├── Gunicorn
    ├── Nginx
    ├── HTTPS
    └── production deployment

dependencies.py     ← NEW
    └── Dependency/version/vulnerability analysis


_is_sensitive_route
_find_unprotected_sensitive_routes
_find_unprotected_sensitive_routes_auth
_detect_authentication_signals
_contains_authentication_signal
_find_authentication_hooks
_analyze_project_authentication
_analyze_project_authentication_routes
_has_authentication_decorator


---is_not_relevant---
_is_sensitive_route



---is_relevant---
_find_unprotected_sensitive_routes_auth

## -----------------------------------------------------------------------------------------------

Every project that I do for clients should
- Get more customers
- Make customer worth more
- Cut costs


share what you're building
what it does, how it works

# PROMPT (OUTREACH TEMPLATE)

Act as a B2B outreach copywriter. Write me a casual friendly first touch message for X warm contact

I'm a one person AI consultant. I just built this specific thing. My goal is not to pitch this prospect. It is to get on a 20 mimute call to learn about their business and show them what I built.

Keep it under 100 words. No corporate speak, no synergy or leverage. Just write it like a real person who actually built something.


Hey, I'm targetting this {specific niche} and they struggle with this {specific problem}.

Help me scope the smallest valuable product I could ship in two weeks. As a solo founder, give me:

- The core feature that solves 80% of the pain.
- Features I should explicitly not build in V1
- The tech stack you'd recommend for a non-technical founder using claude code.
- Potential competitors and how I differentiate

## -----------------------------------------------------------------------------------------------


### 1. We need a complete analyzer inventory

- Flask architecture
- Database
- Security 
- Performance 
- Configuration
- Dependencies
- Testing 
- Deployment 
- Observability 
- API

### 2. The MCP interface needs to be considered a first-class deliverable

The MCP server needs to expose useful operations such as conceptually:

- analyze_project
- analyze_security 
- analyze_database
- analyze_architecture
- get_findings
- get_summary

### 3. We need a unified production-readiness model 

# The user ultimately wants something like:

Production Readiness
──────────────────────
Architecture       92%
Security            84%
Database            78%
Performance         71%
Configuration       90%
Deployment          65%
Testing             82%

Overall             81%

with 

Critical blockers
Warnings
Recommendations
Evidence

### 4. Cross-analyzer intelligence

### 5. We need a real-world acceptance test

* The test should ultimately look conceptually like:

flask-production-mcp
        │
        ▼
   food_store/
        │
        ├── Flask architecture
        ├── routes
        ├── blueprints
        ├── database
        ├── security
        ├── configuration
        └── deployment
             │
             ▼
      production report

| Area                           | Status                    |
| ------------------------------ | ------------------------- |
| AST/static-analysis foundation | 🟢 Strong                 |
| Flask architecture discovery   | 🟢 Strong                 |
| Route discovery                | 🟢 Strong                 |
| Blueprint resolution           | 🟢 Strong                 |
| Duplicate route detection      | 🟢 Done                   |
| Security baseline              | 🟢 Strong                 |
| Authentication analysis        | 🟢 Good                   |
| Rate-limit analysis            | 🟢 Good                   |
| Database analysis              | 🟢 Substantial            |
| Cross-file analysis            | 🟢 Emerging/strong        |
| Finding model                  | 🟢 Existing               |
| Scoring/summary                | 🟢 Existing               |
| MCP exposure                   | 🟡 **Needs verification** |
| Unified production assessment  | 🟡 **Needs verification** |
| Cross-analyzer correlation     | 🟡 **Needs work**         |
| Real-project acceptance test   | 🔴 **Not done yet**       |
| Hardening/refactoring          | ⏸️ **Not priority**       |




So the project is not yet at its original intended completion point, assuming the goal was to build an MCP that can inspect a Flask application comprehensively for production readiness.

| Capability                    | Implemented | Exposed through MCP |
| ----------------------------- | ----------: | ------------------: |
| Flask project discovery       |           ✅ |                   ✅ |
| Application factory detection |           ✅ |                   ✅ |
| Blueprint detection           |           ✅ |                   ✅ |
| Route discovery               |           ✅ |                   ✅ |
| Blueprint URL prefixes        |           ✅ |                   ✅ |
| Duplicate route detection     |           ✅ |                   ✅ |
| Debug configuration detection |           ✅ |                   ✅ |
| Security analysis             |           ✅ |                   ✅ |
| Hardcoded secrets             |           ✅ |                   ✅ |
| Dangerous calls               |           ✅ |                   ✅ |
| Pickle deserialization        |           ✅ |                   ✅ |
| Rate limiting                 |           ✅ |                   ✅ |
| Authentication                |           ✅ |                   ✅ |
| Sensitive routes              |           ✅ |                   ✅ |
| Database models               |           ✅ |                   ❌ |
| Relationships                 |           ✅ |                   ❌ |
| Index analysis                |           ✅ |                   ❌ |
| Raw SQL detection             |           ✅ |                   ❌ |
| Query analysis                |           ✅ |                   ❌ |
| N+1 detection                 |           ✅ |                   ❌ |
| Code quality                  |           ✅ |                   ❌ |
| Bare `except`                 |           ✅ |                   ❌ |
| Broad exceptions              |           ✅ |                   ❌ |
| `print()` calls               |           ✅ |                   ❌ |
| `breakpoint()` calls          |           ✅ |                   ❌ |
| Assertions                    |           ✅ |                   ❌ |
| TODO markers                  |           ✅ |                   ❌ |
| Unified production audit      |           ❌ |                   ❌ |



## -----IMMEDIATE ROADMAP-------

[✓] Flask analyzer
[✓] Security analyzer
[✓] Database analyzer
[✓] Code-quality analyzer
[✓] Finding model
[✓] Security service
[✓] Basic MCP server
[✓] 73 tests passing

        ↓ NEXT

[ ] Expose database analyzer through MCP
[ ] Expose code-quality analyzer through MCP
[ ] Decide/finalize unified audit API
[ ] Build unified production-readiness audit
[ ] Add MCP end-to-end tests
[ ] Run against a real Flask application
[ ] Validate findings/score
[ ] Documentation/examples
[ ] Package/install test
[ ] Final v1 release checklist


## What you have today

* The current architecture is:

                    MCP SERVER
                        │
             ┌──────────┴──────────┐
             │                     │
    inspect_flask_project    audit_security
             │                     │
             ▼                     ▼
       flask analyzer       security service
                                   │
                                   ▼
                           security analyzer
                                   │
                                   ▼
                              AuditResult


## WHERE WE ARE NOW 
* REMAINING WORK:

ANALYSIS ENGINE
────────────────────────────
✓ Flask analysis
✓ Security analysis
✓ Database analysis
✓ Code-quality analysis
✓ Finding model
✓ Scoring
✓ Recommendations
✓ Error handling
✓ Tests


MCP PRODUCT
────────────────────────────
✓ MCP server
✓ Flask inspection tool
✓ Security audit tool
□ Database audit tool
□ Code-quality audit tool
□ Unified project audit
□ MCP integration tests
□ Real-project validation
□ Documentation
□ Package/install validation
□ v1 release


SECURITY
────────────────────────────
✓ Current scope is sufficient
✓ 73 tests passing
→ STOP ADDING FEATURES FOR NOW


## -----------------------------------------------------------

CONTEXT - You, Your Business, Your Customers
- about-me.md
- business-info.md
- ideal-customer.md
- offers.md
- brand-voice.md

business-context/
├── about_me.md
├── business_info.md
├── ideal_customer.md
├── offers.md
├── brand_voice.md
├── positioning.md
├── value_proposition.md
├── products_services.md
├── customer_pain_points.md
├── customer_journey.md
├── sales_process.md
├── marketing_strategy.md
├── content_strategy.md
├── competitive_advantage.md
├── business_goals.md
├── business_principles.md
├── founder_story.md
├── objection_handling.md
├── faq.md
├── case_studies.md
├── proof_and_credibility.md
├── terminology.md
├── do_and_dont.md
└── context_index.md

├── technical_capabilities.md
├── automation_expertise.md
├── ai_capabilities.md
├── target_industries.md
├── project_qualification.md
├── pricing_philosophy.md
├── client_selection.md
└── future_vision.md

I want you to build a bunch of markdown files for my business. Interview me to extract the information from my brain to build it

TOOLS - MCP Connector For Apps

SKILLS - You SOPs, Your Special Sauce




### ------------------------------------------------------------

A systems-minded builder who creates clarity from complexity, uses technology to compress time, and wants to give businesses better ways to solve problems and scale.

                                -------

A small or medium-sized business that already has traction, is constrained by manual processes, is willing to invest $3k–$10k in solving meaningful problems, and has the ambition to grow substantially.

Technology should create productive capacity, not merely reduce effort.

Technology is the tool. Business improvement is the objective.

We build automation solutions and help growing businesses scale.