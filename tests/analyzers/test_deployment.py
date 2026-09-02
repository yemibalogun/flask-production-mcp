"""Tests for the deployment-configuration analyzer."""

from __future__ import annotations

from pathlib import Path

from flask_production_mcp.analyzers.deployment import analyze_deployment


def _write(project: Path, rel: str, content: str) -> None:
    path = project / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _ids(project: Path) -> list[str]:
    return sorted(f.id for f in analyze_deployment(project))


def test_clean_dockerfile_has_no_findings(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Dockerfile",
        "FROM python:3.12-slim\n"
        "ENV PYTHONUNBUFFERED=1\n"
        "RUN adduser --system app\n"
        "USER app\n"
        'CMD ["gunicorn", "-b", "0.0.0.0:8000", "wsgi:app"]\n',
    )

    assert analyze_deployment(tmp_path) == []


def test_flags_missing_user(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Dockerfile",
        'FROM python:3.12-slim\nCMD ["gunicorn", "wsgi:app"]\n',
    )

    assert "DEPLOY-DOCK-001" in _ids(tmp_path)


def test_flags_latest_base_image(tmp_path: Path) -> None:
    _write(tmp_path, "Dockerfile", "FROM python:latest\nUSER app\n")
    assert "DEPLOY-DOCK-002" in _ids(tmp_path)

    _write(tmp_path, "Dockerfile", "FROM ubuntu\nUSER app\n")
    assert "DEPLOY-DOCK-002" in _ids(tmp_path)


def test_flags_dev_server_as_container_command(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Dockerfile",
        'FROM python:3.12-slim\nUSER app\nCMD ["python", "run.py"]\n',
    )

    assert "DEPLOY-DOCK-003" in _ids(tmp_path)


def test_gunicorn_entrypoint_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Dockerfile",
        "FROM python:3.12-slim\nUSER app\n"
        'CMD ["gunicorn", "-w", "4", "run:app"]\n',
    )

    assert "DEPLOY-DOCK-003" not in _ids(tmp_path)


def test_flags_debug_env_in_dockerfile(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Dockerfile",
        "FROM python:3.12-slim\nUSER app\nENV FLASK_DEBUG=1\n"
        'CMD ["gunicorn", "wsgi:app"]\n',
    )

    assert "DEPLOY-ENV-001" in _ids(tmp_path)


def test_flags_baked_secret(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Dockerfile",
        "FROM python:3.12-slim\nUSER app\n"
        "ENV SECRET_KEY=this-is-a-real-baked-secret\n"
        'CMD ["gunicorn", "wsgi:app"]\n',
    )

    assert "DEPLOY-SEC-001" in _ids(tmp_path)


def test_interpolated_env_is_not_a_secret(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Dockerfile",
        "FROM python:3.12-slim\nUSER app\n"
        "ENV SECRET_KEY=${SECRET_KEY}\n"
        'CMD ["gunicorn", "wsgi:app"]\n',
    )

    assert "DEPLOY-SEC-001" not in _ids(tmp_path)


def test_flags_db_port_published_in_compose(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "docker-compose.yml",
        "services:\n"
        "  web:\n"
        "    build: .\n"
        '    ports:\n      - "8000:8000"\n'
        "  db:\n"
        "    image: postgres:16\n"
        '    ports:\n      - "5432:5432"\n',
    )

    findings = analyze_deployment(tmp_path)
    compose_002 = [f for f in findings if f.id == "DEPLOY-COMPOSE-002"]
    assert len(compose_002) == 1
    assert compose_002[0].line == 9  # the db port mapping, not the web one


def test_flags_gunicorn_reload(tmp_path: Path) -> None:
    _write(tmp_path, "gunicorn.conf.py", "workers = 4\nreload = True\n")
    assert "DEPLOY-GUNI-001" in _ids(tmp_path)


def test_flags_procfile_dev_server(tmp_path: Path) -> None:
    _write(tmp_path, "Procfile", "web: flask run --host 0.0.0.0\n")
    assert "DEPLOY-PROC-001" in _ids(tmp_path)

    _write(tmp_path, "Procfile", "web: gunicorn wsgi:app\n")
    assert "DEPLOY-PROC-001" not in _ids(tmp_path)


def test_flags_committed_env_file(tmp_path: Path) -> None:
    _write(tmp_path, ".env", "SECRET_KEY=abc\n")
    assert "DEPLOY-ENV-002" in _ids(tmp_path)


def test_gitignored_env_file_is_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, ".env", "SECRET_KEY=abc\n")
    _write(tmp_path, ".gitignore", ".env\n")
    assert "DEPLOY-ENV-002" not in _ids(tmp_path)


def test_env_example_is_never_flagged(tmp_path: Path) -> None:
    _write(tmp_path, ".env.example", "SECRET_KEY=\n")
    assert analyze_deployment(tmp_path) == []


# --- nginx ---------------------------------------------------------------


def test_flags_edge_nginx_without_forwarded_headers(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "nginx/nginx.conf",
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        "        proxy_pass http://app:8000;\n"
        "    }\n"
        "}\n",
    )

    ids = _ids(tmp_path)
    assert "DEPLOY-NGINX-002" in ids  # no X-Forwarded-Proto
    assert "DEPLOY-NGINX-003" in ids  # no client_max_body_size
    assert "DEPLOY-NGINX-004" in ids  # listen 80, no redirect


def test_well_configured_proxy_nginx_only_flags_server_tokens(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "nginx/nginx.conf",
        "server {\n"
        "    listen 80;\n"
        "    client_max_body_size 10m;\n"
        "    location / {\n"
        "        proxy_pass http://app:8000;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Forwarded-For "
        "$proxy_add_x_forwarded_for;\n"
        "        proxy_set_header X-Forwarded-Proto $scheme;\n"
        "    }\n"
        "}\n",
    )

    # X-Forwarded-Proto present -> not treated as an edge server, so only
    # the server_tokens hygiene note remains.
    assert _ids(tmp_path) == ["DEPLOY-NGINX-001"]


def test_server_tokens_off_clears_nginx_001(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "nginx/nginx.conf",
        "http {\n    server_tokens off;\n}\n",
    )

    assert "DEPLOY-NGINX-001" not in _ids(tmp_path)
