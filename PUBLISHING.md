# Publishing to PyPI

The package builds cleanly (`uv build` → wheel + sdist) and the metadata
is release-ready. What is left is account setup and the publish itself,
which need your credentials.

## One-time setup (you)

### Option A — Trusted Publishing (recommended, no tokens)

1. Create the project on PyPI by reserving the name once, or let the
   first Trusted-Publishing upload create it.
2. On <https://pypi.org/manage/account/publishing/>, add a **pending
   publisher**:
   - PyPI project name: `flask-production-mcp`
   - Owner: `yemibalogun`
   - Repository: `flask-production-mcp`
   - Workflow name: `publish.yml`
   - Environment: `pypi`
3. In the GitHub repo, create an **Environment** named `pypi`
   (Settings → Environments). Optionally require a reviewer.
4. Push a tag — the workflow below does the rest:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

### Option B — API token

1. Create a PyPI account and a **project-scoped API token**
   (<https://pypi.org/manage/account/token/>).
2. Publish from your machine:
   ```bash
   uv build
   uv publish --token "pypi-…"
   # or: python -m twine upload dist/*
   ```

## Release checklist (each version)

- [ ] Bump `version` in `pyproject.toml`
- [ ] `uv run pytest && uv run mypy src && uv run ruff check src tests`
- [ ] `uv build` and sanity-check `dist/`
- [ ] Install the wheel in a clean venv and run
      `flask-production-mcp audit --help` and `flask-production-mcp serve`
- [ ] Commit, tag `vX.Y.Z`, push the tag
- [ ] Confirm the GitHub release/Action published to PyPI
- [ ] `pip install flask-production-mcp` in a fresh venv, smoke test

## Still yours to do before others can use the hook / Action

- Make the GitHub repo **public**.
- Push a **`v0.1.0` tag** — the README's pre-commit `rev:` and
  `uses: …@v0.1.0` both reference it.
- (Optional) Publish the Action to the GitHub Marketplace.
