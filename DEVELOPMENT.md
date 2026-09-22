# MlinziOps — Development Guide

## Tooling

- Python 3.12+, `pip`, `pytest`, `alembic`, `psql`, `nmap`
- No frontend build step: the SPA is vanilla JS over CDN Chart.js + Font Awesome (see note below).

## Project layout

```text
mlinziops/
├── app/                 # application package
│   ├── main.py          # FastAPI factory, middleware, SSE, page routes
│   ├── config.py        # pydantic-settings
│   ├── database.py      # engine/session base
│   ├── deps.py          # request dependencies (auth/user/RBAC)
│   ├── constants.py     # enums + security headers
│   ├── cli.py           # CLI (create-admin, seed-demo, run-checks…)
│   ├── stream.py        # SSE pub/sub
│   ├── models/          # SQLAlchemy ORM
│   ├── schemas/         # Pydantic v2
│   ├── api/             # routers
│   ├── services/        # business logic
│   └── security/        # hashing, tokens, RBAC, rate limit
├── migrations/          # Alembic (env.py + versions/)
├── scripts/seed_demo.py # labelled demo data
├── static/              # css + js (app.js, pages.js)
├── templates/           # Jinja2 pages
├── tests/               # pytest suite
├── deploy/mlinziops.service
├── Dockerfile / docker-compose.yml / nginx.conf
└── docs (this file set)
```

## Running locally

```bash
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000
```

On Windows for dev, the Nmap scanner and hardening checks (which read `/etc`,
`systemctl`, `journalctl`) degrade gracefully — the rest of the app still works.

## Database workflows

```bash
alembic revision --autogenerate -m "describe change"   # after model edits
alembic upgrade head
alembic downgrade -1
```

> Never edit the DB with `Base.metadata.create_all()` in production — that is test-only.

## Writing a new detection rule

1. Add a `rule_*` function in `app/services/detection_engine.py` returning detection dicts.
2. Register it in `run_detection()`.
3. Add unit tests in `tests/test_detection.py`.
4. The Log Analyzer page picks it up automatically (no frontend change needed).

## Frontend conventions

- Pages live in `static/js/pages.js` keyed by `window.PAGES.<route>`.
- Every UI action calls a real `/api` endpoint — no fake data or dead buttons.
- Escape **all** dynamic text with `esc()` in templates and JS; never inline raw HTML from user data.
- When adding a field to a table, pick the right `sev-*` / `st-*` badge class from `app.css`.

## Offline assets note

The UI references Chart.js and Font Awesome from public CDNs. The in-app preview
iframe blocks external requests, so charts/icons may not render *in the preview*;
they work normally when the app is served over HTTP (local or Nginx). If your lab
is air-gapped, download `chart.umd.min.js` and the webfonts into `static/vendor/`
and update the script/link tags in `templates/*.html`.

## Code style

- Type hints on public functions; keep handlers thin (business logic in services).
- No `shell=True`; parameterized ORM; validate at the boundary (Pydantic).

## Pre-commit checklist

```bash
python -m compileall app scripts
pytest -q
```
