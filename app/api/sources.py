from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.settings.common import (
    MANAGED_SOURCE_TYPES,
    SOURCES,
    get_or_create_source as _get_or_create,
    retire_legacy_seed_sources,
)
from app.db.session import get_db
from app.models.pipeline import IngestEvent
from app.models.source import InputSource
from app.models.vulnerability import Vulnerability
from app.schemas.api import IngestEventOut, SourceCreate, SourceOut, SourceUpdate
from app.services.ingestion import ingest_payload, new_webhook_token
from app.utils.intel_window import allow_cve

router = APIRouter()

FEED_TABS = (
    ("smb", "SMB"),
    ("local", "Local"),
    ("outlook", "Outlook"),
    ("web_api", "ATOM feeds"),
)


def _normalize_cve(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    return text if text.startswith("CVE-") else None


def _cves_for_source(db: Session, source: InputSource, *, scan_raw: bool = False) -> list[str]:
    """Unique CVE IDs tied to a source. Does not load raw_text unless an event has no extracted CVEs."""
    seen: dict[str, None] = {}
    need_raw: list[int] = []
    for event_id, extracted, payload in (
        db.query(IngestEvent.id, IngestEvent.extracted_cves, IngestEvent.payload)
        .filter(IngestEvent.source_id == source.id)
        .all()
    ):
        found = False
        for raw in extracted or []:
            cve = _normalize_cve(raw)
            if cve:
                seen.setdefault(cve, None)
                found = True
        payload = payload if isinstance(payload, dict) else {}
        for key in ("cve_id", "cve", "cveId", "cves"):
            value = payload.get(key)
            if isinstance(value, list):
                for item in value:
                    cve = _normalize_cve(item)
                    if cve:
                        seen.setdefault(cve, None)
                        found = True
            else:
                cve = _normalize_cve(value)
                if cve:
                    seen.setdefault(cve, None)
                    found = True
        for rec in payload.get("records") or []:
            if isinstance(rec, dict):
                cve = _normalize_cve(rec.get("cve_id"))
                if cve:
                    seen.setdefault(cve, None)
                    found = True
        if scan_raw and not found:
            need_raw.append(event_id)
    if need_raw:
        from app.utils.cve import extract_cves

        for start in range(0, len(need_raw), 400):
            chunk = need_raw[start : start + 400]
            for raw_text, in (
                db.query(IngestEvent.raw_text).filter(IngestEvent.id.in_(chunk)).all()
            ):
                if not raw_text:
                    continue
                for cve in extract_cves(str(raw_text)):
                    seen.setdefault(cve, None)
    for (cve_id,) in db.query(Vulnerability.cve_id).filter(Vulnerability.source_name == source.name).all():
        cve = _normalize_cve(cve_id)
        if cve:
            seen.setdefault(cve, None)
    return [cve for cve in seen if allow_cve(cve)]


def _feed_payload(db: Session, key: str) -> dict[str, Any]:
    name, _source_type, description = SOURCES[key]
    source = _get_or_create(db, key)
    cves = _cves_for_source(db, source, scan_raw=True)
    last_event = getattr(source, "last_event_at", None)
    return {
        "key": key,
        "name": source.name or name,
        "label": dict(FEED_TABS)[key],
        "description": description,
        "enabled": bool(source.enabled),
        "event_count": int(getattr(source, "event_count", 0) or 0),
        "last_event_at": last_event.isoformat() if last_event else None,
        "last_error": getattr(source, "last_error", None),
        "cve_count": len(cves),
        "cves": cves,
    }


@router.get("/feeds")
def list_feeds(db: Session = Depends(get_db)) -> dict[str, Any]:
    retire_legacy_seed_sources(db)
    db.commit()
    return {"feeds": [_feed_payload(db, key) for key, _label in FEED_TABS]}


@router.get("/sources/kpis")
def sources_kpis(db: Session = Depends(get_db)) -> dict[str, Any]:
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import func

    hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    managed = InputSource.source_type.in_(MANAGED_SOURCE_TYPES)
    active = (
        db.query(func.count(InputSource.id))
        .filter(InputSource.enabled.is_(True), managed)
        .scalar()
        or 0
    )
    recent = (
        db.query(func.count(IngestEvent.id)).filter(IngestEvent.received_at >= hour_ago).scalar() or 0
    )
    failed_events = (
        db.query(func.count(IngestEvent.id))
        .filter(IngestEvent.status == "failed", IngestEvent.received_at >= hour_ago)
        .scalar()
        or 0
    )
    failed_sources = (
        db.query(func.count(InputSource.id))
        .filter(
            managed,
            InputSource.enabled.is_(True),
            InputSource.last_error.isnot(None),
            InputSource.last_error != "",
        )
        .scalar()
        or 0
    )
    rate = f"{(recent / 60):.1f} docs/min" if recent else "0 docs/min"
    return {
        "active_sources": int(active),
        "recent_events_hour": int(recent),
        "avg_rate": rate,
        "recent_errors": int(failed_events + failed_sources),
    }


@router.get("/sources", response_model=list[SourceOut])
def list_sources(db: Session = Depends(get_db)) -> list[SourceOut]:
    retire_legacy_seed_sources(db)
    sources = [_get_or_create(db, key) for key in SOURCES]
    db.commit()
    out: list[SourceOut] = []
    for source in sources:
        item = SourceOut.model_validate(source)
        out.append(item.model_copy(update={"cve_count": len(_cves_for_source(db, source, scan_raw=False))}))
    return out


@router.post("/sources", response_model=SourceOut)
def create_source(body: SourceCreate, db: Session = Depends(get_db)) -> InputSource:
    source = InputSource(**body.model_dump())
    if source.source_type == "webhook":
        source.webhook_token = new_webhook_token()
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


@router.patch("/sources/{source_id}", response_model=SourceOut)
def update_source(source_id: int, body: SourceUpdate, db: Session = Depends(get_db)) -> InputSource:
    source = db.get(InputSource, source_id)
    if not source:
        raise HTTPException(404, "Source not found")
    for key, value in body.model_dump(exclude_unset=True).items():
        setattr(source, key, value)
    db.commit()
    db.refresh(source)
    return source


@router.post("/sources/{source_id}/toggle", response_model=SourceOut)
def toggle_source(source_id: int, db: Session = Depends(get_db)) -> InputSource:
    source = db.get(InputSource, source_id)
    if not source:
        raise HTTPException(404, "Source not found")
    source.enabled = not source.enabled
    if not source.enabled:
        source.last_error = None
    db.commit()
    db.refresh(source)
    return source


@router.get("/sources/{source_id}/events", response_model=list[IngestEventOut])
def source_events(source_id: int, db: Session = Depends(get_db)) -> list[IngestEvent]:
    return (
        db.query(IngestEvent)
        .filter(IngestEvent.source_id == source_id)
        .order_by(IngestEvent.received_at.desc())
        .limit(50)
        .all()
    )


@router.post("/sources/{source_id}/test", response_model=IngestEventOut)
def test_source(source_id: int, db: Session = Depends(get_db)) -> IngestEvent:
    source = db.get(InputSource, source_id)
    if not source:
        raise HTTPException(404, "Source not found")
    sample = {
        "cve_id": "CVE-2024-3094",
        "summary": "Test ingest from EVulnTasker dashboard",
        "vendor": "Tukaani",
        "product": "xz",
    }
    return ingest_payload(db, source, payload=sample, raw_text="Test event CVE-2024-3094")
