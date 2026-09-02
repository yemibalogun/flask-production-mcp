"""Deployment configuration checks.

Looks at the files that actually put a Flask app into production - the
Dockerfile, docker-compose, the Gunicorn config, a Procfile, entrypoint
scripts - for the footguns that make a container run as root, ship the
Werkzeug development server, or bake a secret into an image layer.

Everything is text scanning; nothing is executed.
"""

from __future__ import annotations

import re
from pathlib import Path

from flask_production_mcp.analyzers.exclusions import should_exclude_path
from flask_production_mcp.models.findings import (
    Confidence,
    Finding,
    Severity,
)

# A command that starts the Flask/Werkzeug development server rather than a
# real WSGI server.
_DEV_SERVER = re.compile(
    r"""
      flask\s+run
    | python[0-9.]*\s+(?:-m\s+flask\b|[^\n]*\b(?:run|app|wsgi|manage)\.py)
    | werkzeug
    | app\.run\(
    | --reload\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

_PROD_SERVER = re.compile(
    r"\b(gunicorn|uwsgi|uvicorn|waitress|hypercorn|granian|mod_wsgi)\b",
    re.IGNORECASE,
)

_SECRET_ENV_NAME = re.compile(
    r"(SECRET|PASSWORD|PASSWD|_KEY|API_KEY|TOKEN|ACCESS_KEY)",
    re.IGNORECASE,
)

_PLACEHOLDER = {
    "",
    "changeme",
    "change-me",
    "chang_me",
    "password",
    "secret",
    "your-secret",
    "your_secret_key",
    "xxx",
    "todo",
    "replace_me",
    "replace-me",
}


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _iter_deploy_files(root: Path) -> list[Path]:
    wanted_names = {
        "dockerfile",
        "procfile",
        "entrypoint.sh",
        "docker-entrypoint.sh",
        "start.sh",
        "run.sh",
        "boot.sh",
    }
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or should_exclude_path(path, root):
            continue
        name = path.name.lower()
        if (
            name in wanted_names
            or name.startswith("dockerfile")
            or re.match(r"docker-compose.*\.ya?ml$", name)
            or re.match(r"compose.*\.ya?ml$", name)
            or re.match(r"gunicorn.*\.(py|conf)$", name)
            or re.match(r".*\.env(\..+)?$", name)
        ):
            files.append(path)
    return files


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Dockerfile
# ---------------------------------------------------------------------------


def _check_dockerfile(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()

    instructions = [
        ln.strip()
        for ln in lines
        if ln.strip() and not ln.strip().startswith("#")
    ]

    for number, raw in enumerate(lines, start=1):
        m = re.match(r"\s*FROM\s+(\S+)", raw, re.I)
        if not m:
            continue
        image = m.group(1)
        if image.lower() == "scratch":
            continue
        tag = image.split("@")[0].rsplit(":", 1)
        if len(tag) == 1 or tag[1].lower() in {"latest", ""}:
            findings.append(
                Finding(
                    id="DEPLOY-DOCK-002",
                    category="deployment",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title="Base image is untagged or pinned to :latest",
                    description=(
                        f"`FROM {image}` is not pinned to a specific "
                        "version, so a rebuild can silently pull a "
                        "different base image."
                    ),
                    recommendation=(
                        "Pin an explicit tag (ideally a digest), e.g. "
                        "`FROM python:3.12-slim`."
                    ),
                    file=str(path),
                    line=number,
                    metadata={"image": image},
                )
            )

    if not any(re.match(r"USER\s+\S+", ln, re.I) for ln in instructions):
        findings.append(
            Finding(
                id="DEPLOY-DOCK-001",
                category="deployment",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="Dockerfile has no USER - the container runs as root",
                description=(
                    "No USER instruction was found, so the process runs as "
                    "root inside the container. A container escape or an RCE "
                    "then starts from root."
                ),
                recommendation=(
                    "Create an unprivileged user and switch to it before "
                    "CMD, e.g. `RUN adduser --system app` then `USER app`."
                ),
                file=str(path),
                line=None,
                metadata={},
            )
        )

    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if stripped.startswith("#") or not stripped:
            continue
        upper = stripped.upper()

        if upper.startswith(("CMD", "ENTRYPOINT")):
            # Normalise JSON-array form: CMD ["python", "run.py"] -> a
            # plain command string the dev-server regex can match.
            normalised = re.sub(r"""["',\[\]]+""", " ", stripped)
            if _DEV_SERVER.search(normalised) and not _PROD_SERVER.search(
                normalised
            ):
                findings.append(
                    Finding(
                        id="DEPLOY-DOCK-003",
                        category="deployment",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title="Container command starts the Flask dev server",
                        description=(
                            "The image's CMD/ENTRYPOINT runs the Werkzeug "
                            "development server. It is single-threaded, "
                            "leaks tracebacks, and is not built to face "
                            "real traffic."
                        ),
                        recommendation=(
                            "Run a WSGI server: "
                            '`CMD ["gunicorn", "-w", "4", "-b", '
                            '"0.0.0.0:8000", "wsgi:app"]`.'
                        ),
                        file=str(path),
                        line=number,
                        metadata={"instruction": stripped[:160]},
                    )
                )

        if upper.startswith(("ENV", "ARG")):
            _flag_debug_env(path, number, stripped, findings)
            _flag_secret_env(path, number, stripped, findings, kind="Docker")

    return findings


# ---------------------------------------------------------------------------
# Shared ENV helpers (Dockerfile + compose + .env)
# ---------------------------------------------------------------------------


def _env_pairs(line: str) -> list[tuple[str, str]]:
    body = re.sub(r"^\s*(ENV|ARG)\s+", "", line, flags=re.I)
    pairs: list[tuple[str, str]] = []
    for chunk in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*([^\s]+)", body):
        pairs.append((chunk[0], chunk[1].strip().strip("'\"")))
    return pairs


def _flag_debug_env(
    path: Path, line_no: int, line: str, findings: list[Finding]
) -> None:
    for name, value in _env_pairs(line):
        upper_name = name.upper()
        low = value.lower()
        is_debug = (
            upper_name == "FLASK_DEBUG"
            and low in {"1", "true", "yes", "on"}
        ) or (upper_name == "FLASK_ENV" and low == "development")
        if is_debug:
            findings.append(
                Finding(
                    id="DEPLOY-ENV-001",
                    category="deployment",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title=f"Development mode enabled via {name}",
                    description=(
                        f"{name}={value} turns on Flask debug mode in the "
                        "deployment environment, exposing the interactive "
                        "debugger (arbitrary code execution)."
                    ),
                    recommendation=(
                        f"Remove {name} from the deployment config, or set "
                        "it to a production value."
                    ),
                    file=str(path),
                    line=line_no,
                    metadata={"variable": name, "value": value},
                )
            )


def _flag_secret_env(
    path: Path,
    line_no: int,
    line: str,
    findings: list[Finding],
    kind: str,
) -> None:
    for name, value in _env_pairs(line):
        if not _SECRET_ENV_NAME.search(name):
            continue
        if value.startswith("${") or value.startswith("$("):
            continue  # interpolated - fine
        if value.lower() in _PLACEHOLDER or len(value) < 8:
            continue
        findings.append(
            Finding(
                id="DEPLOY-SEC-001",
                category="deployment",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                title=f"Hardcoded secret in {kind} config: {name}",
                description=(
                    f"{name} is set to a literal value in {path.name}. "
                    "Anyone with the repo (or an image layer) has the "
                    "secret, and rotating it means a rebuild."
                ),
                recommendation=(
                    f"Pass {name} in at runtime from a secret store or an "
                    "untracked env file; reference it as ${{{name}}}."
                ),
                file=str(path),
                line=line_no,
                metadata={"variable": name},
            )
        )


# ---------------------------------------------------------------------------
# docker-compose
# ---------------------------------------------------------------------------

_DB_IMAGE = re.compile(
    r"image:\s*['\"]?(postgres|mysql|mariadb|mongo|redis|memcached)",
    re.IGNORECASE,
)


_PORT_MAPPING = re.compile(r'-\s*["\']?\d+:\d+')
_SERVICE_KEY = re.compile(r"^(\s+)([A-Za-z_][\w-]*):\s*(#.*)?$")


def _check_compose(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()

    # Find each service block: a `<name>:` key, then everything indented
    # deeper than it until the next key at the same or shallower indent.
    blocks: list[tuple[int, int]] = []
    open_blocks: list[tuple[int, int]] = []  # (indent, start_line)
    for idx, raw in enumerate(lines):
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        while open_blocks and indent <= open_blocks[-1][0]:
            block_indent, start = open_blocks.pop()
            blocks.append((start, idx))
        m = _SERVICE_KEY.match(raw)
        if m:
            open_blocks.append((len(m.group(1)), idx))
    for _, start in open_blocks:
        blocks.append((start, len(lines)))

    db_ranges = [
        (start, end)
        for start, end in blocks
        if any(_DB_IMAGE.search(lines[i]) for i in range(start, end))
    ]

    def in_db_service(index: int) -> bool:
        return any(start <= index < end for start, end in db_ranges)

    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if _PORT_MAPPING.match(stripped) and in_db_service(number - 1):
            findings.append(
                Finding(
                    id="DEPLOY-COMPOSE-002",
                    category="deployment",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title="Database port published to the host",
                    description=(
                        "A database service maps a port to the host in "
                        f"{path.name}. That exposes the database beyond the "
                        "compose network, often to the public interface."
                    ),
                    recommendation=(
                        "Drop the `ports:` mapping for internal services; "
                        "other containers reach them over the compose "
                        "network by service name. Use `expose:` if needed."
                    ),
                    file=str(path),
                    line=number,
                    metadata={},
                )
            )

        _flag_debug_env(path, number, stripped, findings)
        if ":" in stripped and not stripped.endswith(":"):
            _flag_secret_env(
                path,
                number,
                "ENV " + stripped.replace(":", "=", 1),
                findings,
                kind="compose",
            )

    return findings


# ---------------------------------------------------------------------------
# Gunicorn config
# ---------------------------------------------------------------------------


def _check_gunicorn(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    match = re.search(r"^\s*reload\s*=\s*True", text, re.MULTILINE)
    if match:
        findings.append(
            Finding(
                id="DEPLOY-GUNI-001",
                category="deployment",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Gunicorn `reload = True` in the config",
                description=(
                    "The auto-reloader watches the filesystem and restarts "
                    "workers on any change. It is a development convenience "
                    "and adds overhead and instability in production."
                ),
                recommendation="Set `reload = False` (or remove it).",
                file=str(path),
                line=_line_of(text, match.start()),
                metadata={},
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Procfile / entrypoint scripts
# ---------------------------------------------------------------------------


def _check_process_file(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if _DEV_SERVER.search(line) and not _PROD_SERVER.search(line):
            findings.append(
                Finding(
                    id="DEPLOY-PROC-001",
                    category="deployment",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    title=f"{path.name} launches the Flask dev server",
                    description=(
                        f"{path.name} starts the app with the Werkzeug "
                        "development server instead of a WSGI server."
                    ),
                    recommendation=(
                        "Start Gunicorn/uWSGI here, e.g. "
                        "`web: gunicorn wsgi:app`."
                    ),
                    file=str(path),
                    line=number,
                    metadata={"command": line[:160]},
                )
            )
    return findings


# ---------------------------------------------------------------------------
# .env
# ---------------------------------------------------------------------------


def _check_env_file(root: Path, path: Path) -> list[Finding]:
    name = path.name.lower()
    if name != ".env":  # .env.example / .env.sample are fine
        return []

    gitignore = root / ".gitignore"
    ignored = False
    if gitignore.is_file():
        content = _read(gitignore) or ""
        ignored = any(
            line.strip() in {".env", "*.env", ".env*"}
            for line in content.splitlines()
        )
    if ignored:
        return []

    return [
        Finding(
            id="DEPLOY-ENV-002",
            category="deployment",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            title="A .env file is present and not gitignored",
            description=(
                "A .env file sits in the project and .gitignore does not "
                "exclude it, so real credentials are one `git add` away "
                "from the history."
            ),
            recommendation=(
                "Add `.env` to .gitignore and commit a `.env.example` with "
                "placeholder values instead."
            ),
            file=str(path),
            line=None,
            metadata={},
        )
    ]


def analyze_deployment(project_path: str | Path) -> list[Finding]:
    """Scan a project's deployment configuration files."""

    root = Path(project_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Deployment analysis root is invalid: {root}")

    findings: list[Finding] = []

    for path in _iter_deploy_files(root):
        name = path.name.lower()
        text = _read(path)
        if text is None:
            continue

        if name.startswith("dockerfile"):
            findings.extend(_check_dockerfile(path, text))
        elif re.match(r"(docker-)?compose.*\.ya?ml$", name):
            findings.extend(_check_compose(path, text))
        elif re.match(r"gunicorn.*\.(py|conf)$", name):
            findings.extend(_check_gunicorn(path, text))
        elif name == "procfile" or name.endswith(".sh"):
            findings.extend(_check_process_file(path, text))
        elif ".env" in name:
            findings.extend(_check_env_file(root, path))

    return findings
