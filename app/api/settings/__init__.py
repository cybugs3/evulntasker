"""Settings API — aggregated router."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.settings import database, feeds, integrations
from app.api.settings.common import SOURCES, get_or_create_source, public_source, retire_legacy_seed_sources
from app.api.settings.feeds import pull_local_files, pull_outlook, pull_smb_files, pull_web_api
from app.api.settings.integrations import assets_payload, ticketing_payload
from app.config import get_settings as get_app_settings
from app.db.session import get_db

# Backward-compatible aliases used by sources.py / older imports
_get_or_create = get_or_create_source

router = APIRouter()
router.include_router(database.router)
router.include_router(feeds.router)
router.include_router(integrations.router)


def _message_payload() -> dict[str, Any]:
    from app.services.mail_templates import SAMPLE_CONTEXT, load_templates, tokens_payload

    return {
        "templates": load_templates(),
        "tokens": tokens_payload(),
        "sample": SAMPLE_CONTEXT,
    }


def _intel_sources(db: Session) -> list[dict[str, Any]]:
    from app.services.intel_sources import ensure_intel_sources, lookup_rows, public_intel_source

    try:
        ensure_intel_sources(db)
    except Exception:
        db.rollback()
    return [public_intel_source(row) for row in lookup_rows(db)]


@router.get("/settings")
def get_settings(db: Session = Depends(get_db)) -> dict[str, Any]:
    from app.services.database_settings import parse_database_url

    cfg = get_app_settings()
    retire_legacy_seed_sources(db)
    web = get_or_create_source(db, "web_api")
    try:
        from app.services.repo_catalog import ensure_atom_feeds

        web = ensure_atom_feeds(db, source=web)
    except Exception:
        db.rollback()
        web = get_or_create_source(db, "web_api")
    return {
        "postgres": parse_database_url(),
        "smb": public_source(get_or_create_source(db, "smb")),
        "local": public_source(get_or_create_source(db, "local")),
        "outlook": public_source(get_or_create_source(db, "outlook")),
        "web_api": public_source(web),
        "enrichment": {
            "enrichment_enabled": cfg.enrichment_enabled,
            "nvd_enabled": cfg.nvd_enabled,
            "nvd_api_base": cfg.nvd_api_base,
            "nvd_api_key_set": bool(cfg.nvd_api_key),
            "epss_enabled": cfg.epss_enabled,
            "epss_api_base": cfg.epss_api_base,
            "intel_start_date": cfg.intel_start_date,
            "configured": cfg.nvd_configured,
            "epss_configured": cfg.epss_configured,
            "sources": _intel_sources(db),
        },
        "ai": {
            "enabled": cfg.ai_enabled,
            "provider": cfg.ai_provider,
            "enrichment_mode": cfg.ai_enrichment_mode,
            "api_base": cfg.ai_api_base,
            "model": cfg.ai_model,
            "api_key_set": bool(cfg.ai_api_key),
        },
        "assets": assets_payload(cfg),
        "ticketing": ticketing_payload(cfg),
        "message": _message_payload(),
    }


__all__ = [
    "SOURCES",
    "_get_or_create",
    "get_or_create_source",
    "pull_local_files",
    "pull_outlook",
    "pull_smb_files",
    "pull_web_api",
    "router",
]
