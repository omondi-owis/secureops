"""SecureOps application entrypoint (FastAPI).

* Mounts static assets and Jinja2 page templates.
* Global security headers + CSP middleware.
* Centralized exception handlers returning JSON (no stack traces/secrets).
* Server-Sent Events stream for live dashboard updates.
* Background sampler for system_snapshots.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import stream
from app.constants import CSP_HEADER, SECURITY_HEADERS
from app.config import settings
from app.logging_config import configure_logging
from app.api import (
    ai,
    approvals,
    audit,
    auth,
    dashboard,
    events,
    hosts,
    incidents,
    logs,
    playbooks,
    reports,
    scanner,
    settings as settings_api,
    system,
    vulnerabilities,
    wazuh,
)

configure_logging()
logger = logging.getLogger("secureops")

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

_SNAPSHOT_TASK: asyncio.Task | None = None
_SOC_TASK: asyncio.Task | None = None


async def _snapshot_loop() -> None:
    """Persist a system_snapshots row every 60s while the app runs."""
    from app.database import SessionLocal
    from app.models import SystemSnapshot
    from app.services.system_monitor import take_snapshot

    while True:
        try:
            data = take_snapshot()
            with SessionLocal() as db:
                db.add(SystemSnapshot(**data))
                db.commit()
        except Exception:  # pragma: no cover
            logger.exception("Snapshot sampler failed (continuing)")
        await asyncio.sleep(60)


async def _soc_loop() -> None:
    """Autonomous SOC loop (spec §14/§44): collect -> detect -> investigate."""
    from app.services.soc_worker import loop

    try:
        await loop()
    except asyncio.CancelledError:
        raise
    except Exception:  # pragma: no cover
        logger.exception("SOC loop crashed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _SNAPSHOT_TASK, _SOC_TASK
    try:
        from app.services.playbook_engine import seed_default_playbooks
        seed_default_playbooks()
    except Exception:  # pragma: no cover
        logger.exception("Playbook seeding failed (continuing)")
    _SNAPSHOT_TASK = asyncio.create_task(_snapshot_loop())
    _SOC_TASK = asyncio.create_task(_soc_loop())
    logger.info("%s starting (env=%s, ai=%s, autonomy=%s)",
                settings.app_name, settings.app_env,
                settings.ai_provider, settings.autonomy_mode)
    yield
    for t in (_SNAPSHOT_TASK, _SOC_TASK):
        if t:
            t.cancel()
    logger.info("%s stopped", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="SecureOps AI — self-hosted AI-assisted security operations for an authorized cybersecurity lab.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# ---------------------------------------------------------------------------
# Security headers / CSP middleware
# ---------------------------------------------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    headers = dict(SECURITY_HEADERS)
    csp = CSP_HEADER
    if not settings.is_production:
        # Development/lab preview renders inside an iframe; production keeps the
        # strict frame-ancestors 'none' + X-Frame-Options DENY hardening.
        headers.pop("X-Frame-Options", None)
        csp = csp.replace("frame-ancestors 'none';", "frame-ancestors 'self' https:;")
    for header, value in headers.items():
        response.headers.setdefault(header, value)
    response.headers.setdefault("Content-Security-Policy", csp)
    if settings.is_production and settings.cookie_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


@app.middleware("http")
async def add_logging(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api"):
        logger.info("%s %s -> %s", request.method, request.url.path, response.status_code)
    return response


# ---------------------------------------------------------------------------
# Include API routers
# ---------------------------------------------------------------------------
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(system.router)
app.include_router(hosts.router)
app.include_router(scanner.router)
app.include_router(logs.router)
app.include_router(events.router)
app.include_router(wazuh.router)
app.include_router(incidents.router)
app.include_router(vulnerabilities.router)
app.include_router(reports.router)
app.include_router(audit.router)
app.include_router(settings_api.router)
app.include_router(ai.router)
app.include_router(approvals.router)
app.include_router(playbooks.router)


# ---------------------------------------------------------------------------
# Static assets (served by the app in dev; Nginx handles them in prod)
# ---------------------------------------------------------------------------
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ---------------------------------------------------------------------------
# SSE stream: /api/stream
# ---------------------------------------------------------------------------
@app.get("/api/stream")
async def event_stream(request: Request):
    """Server-Sent Events stream for real-time dashboard updates.

    Auth is cookie/token based (EventSource cannot send headers); unauthenticated
    clients get a single 401 entry and the stream closes.
    """
    from app.deps import get_optional_token
    from app.security.authentication import decode_access_token

    token = get_optional_token(request)
    payload = decode_access_token(token) if token else None
    if payload is None:
        async def deny():
            yield 'data: {"type":"unauthorized"}\n\n'

        return StreamingResponse(deny(), media_type="text/event-stream", status_code=401,
                                 headers={"Cache-Control": "no-cache"})

    queue = stream.subscribe()

    async def gen():
        try:
            yield "retry: 5000\n\n"
            yield 'data: {"type":"heartbeat"}\n\n'
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {stream.dumps(data)}\n\n"
                except asyncio.TimeoutError:
                    yield 'data: {"type":"heartbeat"}\n\n'
        finally:
            stream.unsubscribe(queue)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Page routes (Jinja2)
# ---------------------------------------------------------------------------
PAGES = ["dashboard", "hosts", "scanner", "logs", "events", "wazuh",
         "incidents", "vulnerabilities", "reports", "audit", "settings", "profile",
         "ai", "approvals", "playbooks"]


@app.get("/", include_in_schema=False)
async def index(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {})


@app.get("/login", include_in_schema=False)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {})


@app.get("/{page}", include_in_schema=False)
async def generic_page(request: Request, page: str):
    if page in PAGES:
        return templates.TemplateResponse(request, f"{page}.html", {})
    raise StarletteHTTPException(status_code=404, detail="Page not found")


# ---------------------------------------------------------------------------
# Centralized exception handlers (JSON; never leak internals)
# ---------------------------------------------------------------------------
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api"):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail if isinstance(exc.detail, str) else str(exc.detail)},
        )
    if exc.status_code == 404:
        return templates.TemplateResponse(
            request, "error.html", {"code": 404, "detail": "Page not found"},
            status_code=404,
        )
    return JSONResponse(status_code=exc.status_code, content={"detail": str(exc.detail)})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    if request.url.path.startswith("/api"):
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error. Details have been logged server-side."},
        )
    return templates.TemplateResponse(
        request, "error.html",
        {"code": 500, "detail": "Internal server error. Details have been logged server-side."},
        status_code=500,
    )
