"""Shared ingestion helper used by webhooks, API feeds, and email polling."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models.pipeline import IngestEvent
from app.models.source import InputSource
from app.utils.cve import extract_cves
from app.utils.intel_window import allow_cve, parse_published


def new_webhook_token() -> str:
    return secrets.token_urlsafe(24)


def _payload_filename(payload: object) -> str:
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("filename") or "").strip()


def _file_event_for(db: Session, source_id: int, filename: str) -> IngestEvent | None:
    """Newest ingest row for this local/SMB file on the source."""
    name = (filename or "").strip()
    if not name:
        return None
    rows = (
        db.query(IngestEvent)
        .filter(IngestEvent.source_id == source_id)
        .order_by(IngestEvent.id.desc())
        .limit(800)
        .all()
    )
    for event in rows:
        if _payload_filename(getattr(event, "payload", None)) == name:
            return event
    return None


def _other_file_event_ids(db: Session, source_id: int, filename: str, keep_id: int) -> list[int]:
    name = (filename or "").strip()
    if not name:
        return []
    drop: list[int] = []
    rows = (
        db.query(IngestEvent)
        .filter(IngestEvent.source_id == source_id)
        .order_by(IngestEvent.id.desc())
        .limit(800)
        .all()
    )
    for event in rows:
        if event.id == keep_id:
            continue
        if _payload_filename(getattr(event, "payload", None)) == name:
            drop.append(event.id)
    return drop


def _payload_cves(payload: dict[str, Any] | None) -> list[str]:
    if not isinstance(payload, dict):
        return []
    found: list[str] = []
    for key in ("cve", "cve_id", "cveId", "cves"):
        value = payload.get(key)
        if isinstance(value, list):
            found.extend(str(item) for item in value)
        elif value:
            found.append(str(value))
    for row in payload.get("records") or []:
        if isinstance(row, dict) and row.get("cve_id"):
            found.append(str(row.get("cve_id")))
    out: list[str] = []
    seen: set[str] = set()
    for raw in found:
        for cve in extract_cves(raw):
            if cve not in seen:
                seen.add(cve)
                out.append(cve)
    return out


def cves_for_event(event: IngestEvent) -> list[str]:
    """Complete CVE-YYYY-NNNN IDs on an ingest event. Empty means the row is noise."""
    payload = event.payload if isinstance(getattr(event, "payload", None), dict) else {}
    blobs: list[str] = []
    raw = getattr(event, "extracted_cves", None)
    if isinstance(raw, list):
        blobs.extend(str(item) for item in raw)
    elif raw:
        blobs.append(str(raw))
    blobs.extend(_payload_cves(payload))
    text = getattr(event, "raw_text", None) or ""
    if text:
        blobs.append(str(text))
    out: list[str] = []
    seen: set[str] = set()
    for cve in extract_cves("\n".join(blobs)):
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


def queued_cves_for_event(event: IngestEvent) -> list[str]:
    """CVE IDs this event actually queued — not every ID mentioned in the payload text."""
    raw = getattr(event, "extracted_cves", None)
    if isinstance(raw, list) and raw:
        out: list[str] = []
        seen: set[str] = set()
        for item in raw:
            for cve in extract_cves(str(item)):
                if cve not in seen:
                    seen.add(cve)
                    out.append(cve)
        if out:
            return out
    return cves_for_event(event)


# SQLite rejects a statement with more than SQLITE_MAX_VARIABLE_NUMBER binds
# (999 on many builds). Keep IN() lists well under that.
_IN_CHUNK = 400


def _iter_chunks(items: list[int], size: int = _IN_CHUNK):
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _delete_events_by_id(db: Session, event_ids: list[int], chunk_size: int = _IN_CHUNK) -> int:
    from app.models.pipeline import PipelineRun

    ids = list(dict.fromkeys(event_ids))
    if not ids:
        return 0
    deleted = 0
    for chunk in _iter_chunks(ids, chunk_size):
        db.query(PipelineRun).filter(PipelineRun.event_id.in_(chunk)).delete(synchronize_session=False)
        n = db.query(IngestEvent).filter(IngestEvent.id.in_(chunk)).delete(synchronize_session=False)
        deleted += int(n or 0)
        db.flush()
    return deleted


def _delete_events_for_source(db: Session, source_id: int) -> int:
    """Delete every ingest event for a source without a giant IN() list."""
    from app.models.pipeline import PipelineRun

    event_ids = select(IngestEvent.id).where(IngestEvent.source_id == source_id)
    db.execute(delete(PipelineRun).where(PipelineRun.event_id.in_(event_ids)))
    result = db.execute(delete(IngestEvent).where(IngestEvent.source_id == source_id))
    db.expire_all()
    return int(result.rowcount or 0)


def _is_atom_payload(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    return bool(str(payload.get("feed_url") or "").strip() or str(payload.get("entry_id") or "").strip())


def _event_is_duplicate(event: IngestEvent) -> bool:
    """True when this row is a duplicate play, not a first ingest or ATOM refresh."""
    payload = event.payload if isinstance(getattr(event, "payload", None), dict) else {}
    if isinstance(payload, dict) and payload.get("_duplicate"):
        return True
    status = (getattr(event, "status", None) or "").strip().lower()
    if status in {"skipped", "duplicate"} and not _is_atom_payload(payload):
        return True
    return False


def _record_duplicate_event(
    db: Session,
    source: InputSource,
    payload: dict[str, Any],
    raw_text: str,
    stored: list[str],
    *,
    hide_filename: bool = False,
) -> IngestEvent:
    """Persist a skipped ingest so Live Workflow can play Extract, without queueing the pipeline."""
    payload = dict(payload)
    payload["_duplicate"] = True
    payload["_refresh"] = False
    payload["cves"] = stored
    payload["cve_id"] = stored[0]
    filename = _payload_filename(payload)
    if hide_filename and filename:
        payload["_origin_filename"] = filename
        payload.pop("filename", None)
        payload.pop("file_path", None)
    event = IngestEvent(
        source_id=source.id,
        payload=payload,
        raw_text=raw_text,
        status="skipped",
        extracted_cves=stored,
    )
    source.event_count = (source.event_count or 0) + 1
    source.last_event_at = datetime.now(timezone.utc)
    source.last_error = None
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def _recount_source_events(db: Session) -> None:
    from app.models.source import InputSource

    counts = {
        source_id: count
        for source_id, count in db.query(IngestEvent.source_id, func.count(IngestEvent.id))
        .group_by(IngestEvent.source_id)
        .all()
    }
    for source in db.query(InputSource).all():
        source.event_count = int(counts.get(source.id) or 0)


def purge_empty_ingest_events(db: Session, limit: int = 8000) -> int:
    """Delete ingest rows that never got a complete CVE ID."""
    drop_ids: list[int] = []
    rows = db.query(IngestEvent).order_by(IngestEvent.id.desc()).limit(limit).all()
    for event in rows:
        if cves_for_event(event):
            continue
        drop_ids.append(event.id)
    return _delete_events_by_id(db, drop_ids)


def purge_unconfigured_atom_events(db: Session, limit: int = 8000) -> int:
    """Drop leftover NVD/demo rows that were later labeled as ATOM feeds."""
    from app.models.source import InputSource
    from app.services.atom_feed import normalize_feeds

    removed = 0
    sources = db.query(InputSource).filter(InputSource.source_type == "web_api").all()
    for source in sources:
        feeds = normalize_feeds(source.config or {})
        if not feeds:
            removed += _delete_events_for_source(db, source.id)
            continue
        drop_ids: list[int] = []
        events = (
            db.query(IngestEvent.id, IngestEvent.payload)
            .filter(IngestEvent.source_id == source.id)
            .order_by(IngestEvent.id.desc())
            .limit(limit)
            .all()
        )
        for event_id, payload in events:
            if _is_atom_payload(payload):
                continue
            drop_ids.append(event_id)
        removed += _delete_events_by_id(db, drop_ids)
    return removed


def purge_duplicate_ingest_events(db: Session, limit: int = 8000) -> int:
    """Keep the newest ingest row per CVE; delete later repeats of the same ID."""
    seen_cves: set[str] = set()
    seen_files: set[tuple[int, str]] = set()
    seen_dup_cves: set[str] = set()
    drop_ids: list[int] = []
    rows = (
        db.query(IngestEvent)
        .order_by(IngestEvent.received_at.desc(), IngestEvent.id.desc())
        .limit(limit)
        .all()
    )
    for event in rows:
        filename = _payload_filename(getattr(event, "payload", None))
        if filename:
            key = (event.source_id, filename.lower())
            if key in seen_files:
                drop_ids.append(event.id)
            else:
                seen_files.add(key)
            continue
        cves = [cve.upper() for cve in cves_for_event(event)]
        if not cves:
            continue
        if _event_is_duplicate(event):
            if all(cve in seen_cves or cve in seen_dup_cves for cve in cves):
                drop_ids.append(event.id)
                continue
            seen_dup_cves.update(cves)
            continue
        if all(cve in seen_cves for cve in cves):
            drop_ids.append(event.id)
            continue
        seen_cves.update(cves)
    return _delete_events_by_id(db, drop_ids)


def purge_unconfigured_atom_catalog(db: Session) -> int:
    """Remove CVE records that only exist because of the old NVD demo poller."""
    from app.models.source import InputSource
    from app.models.vulnerability import Vulnerability
    from app.services.atom_feed import normalize_feeds

    sources = db.query(InputSource).filter(InputSource.source_type == "web_api").all()
    has_feeds = any(normalize_feeds(source.config or {}) for source in sources)
    atom_names = {(source.name or "").strip().lower() for source in sources}
    atom_names.update({"atom feeds", "nvd api feed", "web api", "generic webhook"})

    removed = 0
    for vuln in db.query(Vulnerability).all():
        name = (vuln.source_name or "").strip().lower()
        from_demo = name in atom_names or "nvd" in name
        if not from_demo:
            continue
        if has_feeds and allow_cve(vuln.cve_id):
            continue
        db.delete(vuln)
        removed += 1
    return removed


def purge_ingest_noise(db: Session) -> int:
    removed = purge_empty_ingest_events(db)
    removed += purge_unconfigured_atom_events(db)
    removed += purge_duplicate_ingest_events(db)
    removed += purge_unconfigured_atom_catalog(db)
    db.expire_all()
    _recount_source_events(db)
    return removed


def _known_cve_ids(db: Session, candidates: list[str]) -> set[str]:
    """CVEs already stored, or currently queued/processing — not old done ingest rows."""
    from app.models.vulnerability import Vulnerability

    wanted = {cve.upper() for cve in candidates}
    if not wanted:
        return set()
    known = {
        row[0].upper()
        for row in db.query(Vulnerability.cve_id).filter(Vulnerability.cve_id.in_(list(wanted))).all()
        if row[0]
    }
    leftover = wanted - known
    if not leftover:
        return known
    pending = (
        db.query(IngestEvent.extracted_cves)
        .filter(IngestEvent.status.in_(("queued", "processing")))
        .order_by(IngestEvent.id.desc())
        .limit(2000)
        .all()
    )
    for (raw,) in pending:
        items = raw if isinstance(raw, list) else [raw] if raw else []
        for item in items:
            cve = str(item).upper()
            if cve in leftover:
                known.add(cve)
        if leftover <= known:
            break
    return known


def cves_recorded_for_file(db: Session, source_id: int, filename: str) -> list[str]:
    """CVE IDs last extracted from this local/SMB filename (ignores duplicate plays)."""
    name = (filename or "").strip()
    if not name:
        return []
    rows = (
        db.query(IngestEvent)
        .filter(IngestEvent.source_id == source_id)
        .order_by(IngestEvent.id.desc())
        .limit(2000)
        .all()
    )
    for event in rows:
        payload = event.payload if isinstance(getattr(event, "payload", None), dict) else {}
        if payload.get("_duplicate"):
            continue
        if str(payload.get("filename") or "").strip() != name:
            continue
        raw = event.extracted_cves if isinstance(event.extracted_cves, list) else []
        if not raw:
            raw = payload.get("cves") or []
            if not isinstance(raw, list):
                raw = [raw] if raw else []
        return [str(item).upper() for item in raw if str(item or "").strip()]
    return []


def skip_unchanged_ingest_file(
    db: Session,
    source_id: int,
    filename: str,
    seen_stamp: str | None,
    current_stamp: str,
) -> bool:
    """Skip an unread local/SMB file when it did not change and its CVEs are still known."""
    if not filename or not current_stamp or seen_stamp != current_stamp:
        return False
    cves = cves_recorded_for_file(db, source_id, filename)
    if not cves:
        return False
    known = _known_cve_ids(db, cves)
    return all(cve in known for cve in cves)


def ingest_payload(
    db: Session,
    source: InputSource,
    payload: dict[str, Any] | None = None,
    raw_text: str = "",
) -> IngestEvent | None:
    payload = payload or {}
    published = parse_published(
        payload.get("published")
        or payload.get("published_at")
        or payload.get("publishedDate")
    )
    found = list(dict.fromkeys(_payload_cves(payload) + extract_cves(raw_text)))
    cves = [cve for cve in found if allow_cve(cve, published)]
    if not cves:
        return None
    refresh = _is_atom_payload(payload)
    filename = _payload_filename(payload)
    queued = cves
    if not refresh:
        known = _known_cve_ids(db, cves)
        queued = [cve for cve in cves if cve.upper() not in known]
    stored = cves if filename else queued
    payload = dict(payload)
    payload["_refresh"] = refresh
    keep = {cve.upper() for cve in (stored or cves)}
    payload["cves"] = stored or cves
    payload["cve_id"] = (stored or cves)[0]
    if isinstance(payload.get("records"), list):
        payload["records"] = [
            row
            for row in payload["records"]
            if isinstance(row, dict) and str(row.get("cve_id") or "").upper() in keep
        ]
    from app.workers.queue import queue
    from sqlalchemy.orm.attributes import flag_modified

    existing = _file_event_for(db, source.id, filename) if filename else None
    if existing:
        extra_ids = _other_file_event_ids(db, source.id, filename, existing.id)
        if not queued:
            return _record_duplicate_event(
                db, source, payload, raw_text, cves, hide_filename=True
            )
        existing.payload = payload
        flag_modified(existing, "payload")
        existing.raw_text = raw_text
        existing.extracted_cves = stored
        flag_modified(existing, "extracted_cves")
        existing.received_at = datetime.now(timezone.utc)
        existing.error = None
        source.last_event_at = datetime.now(timezone.utc)
        source.last_error = None
        if extra_ids:
            _delete_events_by_id(db, extra_ids)
            source.event_count = max(1, (source.event_count or 1) - len(extra_ids))
        existing.status = "queued"
        db.commit()
        db.refresh(existing)
        queue.enqueue(existing.id)
        return existing

    if not queued and not refresh:
        return _record_duplicate_event(db, source, payload, raw_text, cves, hide_filename=False)

    event = IngestEvent(
        source_id=source.id,
        payload=payload,
        raw_text=raw_text,
        status="queued",
        extracted_cves=stored,
    )
    source.event_count = (source.event_count or 0) + 1
    source.last_event_at = datetime.now(timezone.utc)
    source.last_error = None
    db.add(event)
    db.commit()
    db.refresh(event)
    queue.enqueue(event.id)
    return event


class InlineIngestError(ValueError):
    def __init__(self, message: str, *, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def ingest_inline_cve(db: Session, *, cve_id: str = "", sample_text: str = "") -> IngestEvent:
    """Queue a CVE entered by an operator and run the full pipeline."""
    from app.api.settings.common import get_or_create_source

    found = list(dict.fromkeys(extract_cves(cve_id) + extract_cves(sample_text)))
    if not found:
        raise InlineIngestError("Enter a CVE ID such as CVE-2024-1234")
    allowed = [cve for cve in found if allow_cve(cve)]
    if not allowed:
        label = ", ".join(found)
        raise InlineIngestError(f"{label} is older than Ignore CVEs published before")
    source = get_or_create_source(db, "inline")
    if not source.enabled:
        source.enabled = True
    raw_text = (sample_text or "").strip() or "\n".join(allowed)
    payload = {
        "cve_id": allowed[0],
        "cves": allowed,
        "origin": "inline",
    }
    event = ingest_payload(db, source, payload=payload, raw_text=raw_text)
    if event is None:
        label = ", ".join(allowed)
        raise InlineIngestError(f"{label} is already in the system", status_code=409)
    return event


def queue_cve_rerun(db: Session, cve_id: str) -> IngestEvent:
    """Re-queue a CVE that is already in Incoming CVEs so Live Workflow can play it."""
    from app.api.settings.common import get_or_create_source
    from app.models.vulnerability import Vulnerability
    from app.workers.queue import queue

    found = extract_cves(cve_id)
    if not found:
        raise InlineIngestError("Enter a CVE ID such as CVE-2024-1234")
    cve = found[0]
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve).one_or_none()
    if vuln is None:
        raise InlineIngestError("CVE not found", status_code=404)
    source = get_or_create_source(db, "inline")
    if not source.enabled:
        source.enabled = True
    payload = {
        "cve_id": cve,
        "cves": [cve],
        "origin": "inline",
        "_refresh": True,
        "_rerun": True,
    }
    event = IngestEvent(
        source_id=source.id,
        payload=payload,
        raw_text=cve,
        status="queued",
        extracted_cves=[cve],
    )
    source.event_count = (source.event_count or 0) + 1
    source.last_event_at = datetime.now(timezone.utc)
    source.last_error = None
    db.add(event)
    db.commit()
    db.refresh(event)
    queue.enqueue(event.id)
    return event
