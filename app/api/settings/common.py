"""Shared helpers for settings API routes."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models.source import InputSource

SOURCES = {
    "inline": ("Inline CVE", "inline", "CVE IDs entered by an operator. Runs the full pipeline and is saved."),
    "smb": ("SMB share", "smb", "CVE files from an SMB/CIFS share (AD/LDAP)."),
    "local": ("Local folder", "local", "CVE files from a folder on this server."),
    "outlook": ("Outlook / Exchange", "outlook", "On-prem Exchange mailbox listener."),
    "web_api": ("ATOM feeds", "web_api", "ATOM/RSS feeds polled for CVE IDs."),
}

MANAGED_SOURCE_TYPES = {item[1] for item in SOURCES.values()}

POLL_DEFAULTS = {
    "smb": 300,
    "local": 60,
    "outlook": 120,
    "web_api": 3600,
}

_SEED_NAME_BASES = {
    "nvd api feed",
    "generic webhook",
    "outlook advisory inbox",
    "internal scanner",
    "web api",
}


def get_or_create_source(db: Session, key: str) -> InputSource:
    default_name, source_type, description = SOURCES[key]
    source = (
        db.query(InputSource)
        .filter(InputSource.source_type == source_type)
        .order_by(InputSource.id.asc())
        .first()
    )
    if source:
        return source
    source = InputSource(
        name=_unique_source_name(db, default_name),
        description=description,
        enabled=key == "inline",
        config={},
    )
    source.source_type = source_type
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


def _unique_source_name(db: Session, desired: str, exclude_id: int | None = None) -> str:
    name = desired
    suffix = 2
    while True:
        query = db.query(InputSource).filter(InputSource.name == name)
        if exclude_id is not None:
            query = query.filter(InputSource.id != exclude_id)
        if query.first() is None:
            return name
        name = f"{desired} {suffix}"
        suffix += 1


def _seed_base_name(name: str) -> str:
    import re

    return re.sub(r"\s*\(retired(?: \d+)?\)\s*$", "", name or "", flags=re.I).strip().lower()


def _reassign_events(db: Session, from_id: int, to_id: int) -> None:
    from app.models.pipeline import IngestEvent

    if from_id == to_id:
        return
    db.query(IngestEvent).filter(IngestEvent.source_id == from_id).update(
        {IngestEvent.source_id: to_id},
        synchronize_session=False,
    )


def _delete_source_and_events(db: Session, source: InputSource) -> None:
    """Remove a leftover demo source without moving its history onto ATOM feeds."""
    from app.services.ingestion import _delete_events_for_source

    _delete_events_for_source(db, source.id)
    db.delete(source)


def cleanup_input_sources(db: Session) -> int:
    """Merge duplicate feed rows and delete leftover demo sources (NVD API Feed, webhooks, …)."""
    changed = 0
    for key, (_default_name, source_type, _description) in SOURCES.items():
        rows = (
            db.query(InputSource)
            .filter(InputSource.source_type == source_type)
            .order_by(InputSource.id.asc())
            .all()
        )
        if len(rows) <= 1:
            continue
        keep = rows[0]
        for extra in rows[1:]:
            keep.event_count = (keep.event_count or 0) + (extra.event_count or 0)
            _reassign_events(db, extra.id, keep.id)
            db.flush()
            db.delete(extra)
            changed += 1

    leftovers = [
        source
        for source in db.query(InputSource).all()
        if source.source_type not in MANAGED_SOURCE_TYPES
    ]
    for leftover in leftovers:
        _delete_source_and_events(db, leftover)
        changed += 1

    for key, (default_name, source_type, _description) in SOURCES.items():
        source = (
            db.query(InputSource)
            .filter(InputSource.source_type == source_type)
            .order_by(InputSource.id.asc())
            .first()
        )
        if source is None:
            continue
        if _seed_base_name(source.name) in _SEED_NAME_BASES or "(retired)" in (source.name or "").lower():
            source.name = _unique_source_name(db, default_name, exclude_id=source.id)
            changed += 1

    for source in db.query(InputSource).all():
        if source.enabled or not source.last_error:
            continue
        source.last_error = None
        changed += 1
    from app.services.ingestion import purge_ingest_noise

    changed += purge_ingest_noise(db)
    return changed


def retire_legacy_seed_sources(db: Session) -> int:
    return cleanup_input_sources(db)


def apply_display_name(db: Session, source: InputSource, requested: str, key: str) -> None:
    """Set the admin-facing source name shown on Manage Input Sources."""
    from fastapi import HTTPException

    default_name = SOURCES[key][0]
    name = (requested or "").strip() or default_name
    if len(name) > 128:
        name = name[:128]
    if name == source.name:
        return
    clash = (
        db.query(InputSource)
        .filter(InputSource.name == name, InputSource.id != source.id)
        .first()
    )
    if clash:
        raise HTTPException(400, f'Another source is already named "{name}".')
    source.name = name


def public_source(source: InputSource, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = dict(source.config or {})
    password_set = bool(cfg.get("password"))
    token_set = bool(cfg.get("token"))
    cfg.pop("password", None)
    cfg.pop("token", None)
    cfg.pop("seen", None)
    cfg.pop("seen_entries", None)
    cfg.pop("last_poll_at", None)
    if source.source_type == "web_api" or "feeds" in cfg:
        from app.services.atom_feed import public_feeds

        feeds = public_feeds(source.config or {})
        cfg["feeds"] = feeds
        token_set = token_set or any(row.get("token_set") for row in feeds)
        if feeds:
            cfg["url"] = feeds[0]["url"]
    if source.source_type == "smb" or "locations" in cfg:
        from app.integrations.smb import normalize_locations

        locations = normalize_locations(source.config or {})
        cfg["locations"] = locations
        if locations:
            cfg["server"] = locations[0]["server"]
            cfg["share"] = locations[0]["share"]
            cfg["path"] = locations[0]["path"]
    out = {
        "enabled": source.enabled,
        "password_set": password_set,
        "token_set": token_set,
        "poll_seconds": int(cfg.get("poll_seconds") or POLL_DEFAULTS.get(source.source_type, 300)),
        "last_error": getattr(source, "last_error", None),
        "last_event_at": (
            source.last_event_at.isoformat()
            if getattr(source, "last_event_at", None)
            else None
        ),
        "event_count": getattr(source, "event_count", None) or 0,
    }
    out.update(cfg)
    out["name"] = source.name
    if extra:
        out.update(extra)
        out["name"] = source.name
    return out


def record_source_error(source: InputSource, message: str | None) -> None:
    """Store the last pull error. Pause still shows it after a manual Sync now."""
    text = (message or "").strip()
    source.last_error = text or None


def save_source_cfg(source: InputSource, body: BaseModel, keys: list[str]) -> None:
    cfg = dict(source.config or {})
    data = body.model_dump()
    for key in keys:
        if key in {"password", "token"}:
            if data.get(key):
                cfg[key] = data[key]
            continue
        cfg[key] = data.get(key)
    source.config = cfg
    source.last_error = None


def save_env(updates: dict[str, str]) -> None:
    from app.services.database_settings import write_env_values

    write_env_values(updates)


def connection_public(prefix: str, cfg: Any) -> dict[str, Any]:
    """Serialize CMDB/Sonatype/Ticketing connection fields from Settings."""
    password = getattr(cfg, f"{prefix}_password", "") or getattr(cfg, f"{prefix}_api_token", "")
    return {
        "enabled": getattr(cfg, f"{prefix}_enabled", False),
        "host": getattr(cfg, f"{prefix}_host", ""),
        "port": getattr(cfg, f"{prefix}_port", 443),
        "use_tls": getattr(cfg, f"{prefix}_use_tls", True),
        "ignore_cert": getattr(cfg, f"{prefix}_ignore_cert", False),
        "username": getattr(cfg, f"{prefix}_username", ""),
        "password_set": bool(password),
        "api_path": getattr(cfg, f"{prefix}_api_path", ""),
        "legacy_url": getattr(cfg, f"{prefix}_api_url", "") or getattr(cfg, "jira_base_url", ""),
        "base_url": getattr(cfg, f"{prefix}_connection", None).base_url
        if hasattr(cfg, f"{prefix}_connection")
        else getattr(cfg, f"{prefix}_api_url", ""),
    }
