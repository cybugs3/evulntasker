"""Built-in internet intel sources (NVD, EPSS) shown and edited in Settings."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.config import get_settings
from app.models.repository import VulnerabilityRepository

LOOKUP_TYPES = ("nvd", "epss")

DEFAULT_INTEL = [
    dict(
        name="NVD",
        feed_type="nvd",
        endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0",
        enabled=False,
        sync_status="idle",
        raw_count=0,
        notes="National Vulnerability Database 2.0 — CVSS, vendor, product, CWE.",
        config={"intel_managed": True},
    ),
    dict(
        name="FIRST EPSS",
        feed_type="epss",
        endpoint="https://api.first.org/data/v1/epss",
        enabled=False,
        sync_status="idle",
        raw_count=0,
        notes="FIRST Exploit Prediction Scoring System — likelihood of exploitation.",
        config={"intel_managed": True},
    ),
]


def _cfg(row: VulnerabilityRepository) -> dict[str, Any]:
    blob = row.config if isinstance(row.config, dict) else {}
    return dict(blob)


def lookup_rows(db: Session, feed_type: str | None = None) -> list[VulnerabilityRepository]:
    query = db.query(VulnerabilityRepository).filter(
        VulnerabilityRepository.feed_type.in_(LOOKUP_TYPES)
    )
    if feed_type:
        query = query.filter(VulnerabilityRepository.feed_type == feed_type)
    return query.order_by(VulnerabilityRepository.id.asc()).all()


def public_intel_source(row: VulnerabilityRepository) -> dict[str, Any]:
    cfg = _cfg(row)
    return {
        "id": row.id,
        "name": row.name,
        "feed_type": row.feed_type,
        "endpoint": row.endpoint or "",
        "enabled": bool(row.enabled),
        "notes": row.notes or "",
        "api_key_set": bool(cfg.get("api_key")),
        "built_in": row.feed_type in LOOKUP_TYPES,
    }


def ensure_intel_sources(db: Session) -> None:
    """Create NVD/EPSS rows on first run. Do not resurrect sources the operator deleted."""
    from app.api.settings.common import save_env

    settings = get_settings()
    rows = lookup_rows(db)
    if not rows and settings.intel_sources_seeded:
        return

    by_type: dict[str, list[VulnerabilityRepository]] = {}
    for row in rows:
        by_type.setdefault(row.feed_type, []).append(row)
        cfg = _cfg(row)
        if cfg.get("intel_managed"):
            continue
        if row.feed_type == "nvd":
            if settings.nvd_api_base:
                row.endpoint = settings.nvd_api_base
            if settings.nvd_api_key:
                cfg["api_key"] = settings.nvd_api_key
        elif row.feed_type == "epss":
            if settings.epss_api_base:
                row.endpoint = settings.epss_api_base
        cfg["intel_managed"] = True
        row.config = cfg
        flag_modified(row, "config")

    created = False
    if not settings.intel_sources_seeded:
        for spec in DEFAULT_INTEL:
            if spec["feed_type"] in by_type:
                continue
            payload = dict(spec)
            payload["name"] = _unique_name(db, spec["name"])
            payload["enabled"] = False
            if payload["feed_type"] == "nvd":
                payload["endpoint"] = settings.nvd_api_base or payload["endpoint"]
                cfg = dict(payload.get("config") or {})
                if settings.nvd_api_key:
                    cfg["api_key"] = settings.nvd_api_key
                payload["config"] = cfg
            elif payload["feed_type"] == "epss":
                payload["endpoint"] = settings.epss_api_base or payload["endpoint"]
            db.add(VulnerabilityRepository(**payload))
            created = True
        save_env({"INTEL_SOURCES_SEEDED": "true"})

    if created or rows:
        db.commit()


def restore_default_intel_sources(db: Session) -> list[VulnerabilityRepository]:
    """Re-add built-in NVD/EPSS if the operator deleted them. Leaves existing rows alone."""
    have = {row.feed_type for row in lookup_rows(db)}
    added: list[VulnerabilityRepository] = []
    for spec in DEFAULT_INTEL:
        if spec["feed_type"] in have:
            continue
        payload = dict(spec)
        payload["name"] = _unique_name(db, spec["name"])
        row = VulnerabilityRepository(**payload)
        db.add(row)
        added.append(row)
    if added:
        db.commit()
        for row in added:
            db.refresh(row)
    return added


def save_intel_sources(db: Session, items: list[dict[str, Any]]) -> list[VulnerabilityRepository]:
    existing = {row.id: row for row in lookup_rows(db)}
    keep: set[int] = set()
    for raw in items:
        feed_type = str(raw.get("feed_type") or "").strip().lower()
        if feed_type not in LOOKUP_TYPES:
            continue
        endpoint = str(raw.get("endpoint") or "").strip()
        name = str(raw.get("name") or "").strip() or feed_type.upper()
        enabled = bool(raw.get("enabled"))
        notes = str(raw.get("notes") or "")
        ident = raw.get("id")
        row = existing.get(int(ident)) if ident not in (None, "", 0, "0") else None
        if row is None:
            row = VulnerabilityRepository(
                name=_unique_name(db, name),
                feed_type=feed_type,
                endpoint=endpoint,
                enabled=enabled,
                notes=notes,
                sync_status="idle",
                config={"intel_managed": True},
            )
            db.add(row)
            db.flush()
            keep.add(row.id)
        else:
            if row.name != name:
                row.name = _unique_name(db, name, exclude_id=row.id)
            row.feed_type = feed_type
            row.endpoint = endpoint
            row.enabled = enabled
            row.notes = notes
            keep.add(row.id)
        cfg = _cfg(row)
        cfg["intel_managed"] = True
        api_key = raw.get("api_key")
        if isinstance(api_key, str) and api_key.strip():
            cfg["api_key"] = api_key.strip()
        row.config = cfg
        flag_modified(row, "config")

    for ident, row in existing.items():
        if ident not in keep:
            db.delete(row)

    db.commit()
    rows = lookup_rows(db)
    _sync_env(rows)
    return rows


def _unique_name(db: Session, desired: str, exclude_id: int | None = None) -> str:
    name = desired
    suffix = 2
    while True:
        query = db.query(VulnerabilityRepository).filter(VulnerabilityRepository.name == name)
        if exclude_id is not None:
            query = query.filter(VulnerabilityRepository.id != exclude_id)
        if query.first() is None:
            return name
        name = f"{desired} {suffix}"
        suffix += 1


def _sync_env(rows: list[VulnerabilityRepository]) -> None:
    from app.api.settings.common import save_env

    nvd = next((row for row in rows if row.feed_type == "nvd"), None)
    epss = next((row for row in rows if row.feed_type == "epss"), None)
    updates = {
        "NVD_ENABLED": "true" if any(row.feed_type == "nvd" and row.enabled for row in rows) else "false",
        "EPSS_ENABLED": "true" if any(row.feed_type == "epss" and row.enabled for row in rows) else "false",
        "INTEL_SOURCES_SEEDED": "true",
    }
    if nvd and nvd.endpoint:
        updates["NVD_API_BASE"] = nvd.endpoint
        key = _cfg(nvd).get("api_key") or ""
        if key:
            updates["NVD_API_KEY"] = str(key)
    if epss and epss.endpoint:
        updates["EPSS_API_BASE"] = epss.endpoint
    save_env(updates)


def enabled_lookups(feed_type: str) -> list[dict[str, str]]:
    """Enabled lookup endpoints. DB enabled rows win; otherwise .env NVD/EPSS flags."""
    settings = get_settings()
    if not settings.enrichment_enabled:
        return []
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        rows = lookup_rows(db, feed_type)
        out: list[dict[str, str]] = []
        for row in rows:
            if not row.enabled or not (row.endpoint or "").strip():
                continue
            out.append(
                {
                    "name": row.name,
                    "endpoint": row.endpoint.strip(),
                    "api_key": str(_cfg(row).get("api_key") or ""),
                }
            )
        if out:
            return out
    finally:
        db.close()

    if feed_type == "nvd" and settings.nvd_enabled and settings.nvd_api_base:
        return [
            {
                "name": "NVD",
                "endpoint": settings.nvd_api_base,
                "api_key": settings.nvd_api_key or "",
            }
        ]
    if feed_type == "epss" and settings.epss_enabled and settings.epss_api_base:
        return [{"name": "FIRST EPSS", "endpoint": settings.epss_api_base, "api_key": ""}]
    return []


def lookup_active(feed_type: str) -> bool:
    return bool(enabled_lookups(feed_type))
