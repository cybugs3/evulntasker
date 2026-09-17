"""
EVulnTasker FastAPI application.

Exposes:
  * JSON APIs under /api/*
  * English-only dashboard under /
  * Generic webhook listener under /api/webhooks/{token}

A single process hosts HTTP, the asyncio pipeline worker, and APScheduler
so it can be supervised by one systemd unit on RHEL.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import __app_name__, __version__
from app.api.router import api_router
from app.config import get_settings
from app.db.session import init_db
from app.logging_conf import configure_logging
from app.services.seed import seed_if_empty
from app.utils.http_basic import OptionalBasicAuthMiddleware
from app.utils.rate_limit import SensitivePostLimitMiddleware
from app.web.pages import router as pages_router
from app.workers.queue import queue
from app.workers.scheduler import create_scheduler

log = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent


def openapi_kwargs(env: str) -> dict:
    if env == "production":
        return {"docs_url": None, "redoc_url": None, "openapi_url": None}
    return {"docs_url": "/docs", "redoc_url": "/redoc", "openapi_url": "/openapi.json"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    configure_logging()
    settings = get_settings()
    log.info("Starting %s v%s (%s)", __app_name__, __version__, settings.env)
    init_db()
    seed_if_empty()
    await queue.start()
    scheduler = create_scheduler()
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)
    await queue.stop()
    log.info("%s stopped", __app_name__)


app = FastAPI(
    title=__app_name__,
    version=__version__,
    description="Elizarov Vulnerabilities Tasking Manager Platform",
    lifespan=lifespan,
    **openapi_kwargs(get_settings().env),
)
app.add_middleware(SensitivePostLimitMiddleware)
app.add_middleware(OptionalBasicAuthMiddleware)
app.include_router(api_router)
app.include_router(pages_router)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "web" / "static")), name="static")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "version": __version__}
