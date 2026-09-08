"""
Time-based triggers: poll API feeds and the Exchange mailbox.

APScheduler runs inside the FastAPI process so a single systemd unit covers
HTTP, the asyncio worker, and scheduled ingestion.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.config import get_settings
from app.db.session import SessionLocal
from app.integrations.exchange import ExchangeClient
from app.models.repository import VulnerabilityRepository
from app.models.source import InputSource
from app.api.settings.common import POLL_DEFAULTS
from app.services.ingestion import ingest_payload
from app.utils.intel_window import allow_cve, apply_nvd_window, parse_published

log = logging.getLogger(__name__)


def create_scheduler() -> AsyncIOScheduler:
    settings = get_settings()
    # Sync poll jobs (SMB, ATOM, Exchange) must not run on the asyncio loop —
    # they would freeze every HTTP request until the poll returns.
    scheduler = AsyncIOScheduler(
        timezone="UTC",
        executors={"default": ThreadPoolExecutor(max_workers=3)},
        job_defaults={
            "coalesce": True,
            "max_instances": 1,
            "misfire_grace_time": 120,
        },
    )
    start = datetime.now(timezone.utc)

    def later(seconds: int) -> datetime:
        return start + timedelta(seconds=seconds)

    scheduler.add_job(
        poll_exchange,
        "interval",
        seconds=max(60, settings.email_poll_seconds),
        id="poll-exchange",
        replace_existing=True,
        next_run_time=later(25),
    )
    scheduler.add_job(
        poll_smb,
        "interval",
        seconds=min(max(60, settings.feed_poll_seconds), 120),
        id="poll-smb",
        replace_existing=True,
        next_run_time=later(40),
    )
    scheduler.add_job(
        poll_local,
        "interval",
        seconds=min(max(30, settings.feed_poll_seconds), 60),
        id="poll-local",
        replace_existing=True,
        next_run_time=later(15),
    )
    scheduler.add_job(
        poll_outlook,
        "interval",
        seconds=min(max(60, settings.email_poll_seconds), 120),
        id="poll-outlook",
        replace_existing=True,
        next_run_time=later(35),
    )
    scheduler.add_job(
        poll_web_api,
        "interval",
        seconds=60,
        id="poll-web-api",
        replace_existing=True,
        next_run_time=later(50),
    )
    scheduler.add_job(
        poll_inventory,
        "interval",
        seconds=60,
        id="sync-inventory",
        replace_existing=True,
        next_run_time=later(55),
    )
    return scheduler


def poll_api_feeds() -> None:
    """Pull enabled API-feed sources. The actual HTTP fetch is source.config.url."""
    import httpx

    from app.models.vulnerability import Vulnerability

    db = SessionLocal()
    try:
        sources = (
            db.query(InputSource)
            .filter(InputSource.enabled.is_(True), InputSource.source_type == "api_feed")
            .all()
        )
        for source in sources:
            url = (source.config or {}).get("url")
            if not url:
                continue
            try:
                url = apply_nvd_window(url)
                response = httpx.get(url, timeout=30.0, headers=_feed_headers(source))
                response.raise_for_status()
                payload = response.json()
                items = _normalize_feed_items(payload)[:10]
                known = {row[0] for row in db.query(Vulnerability.cve_id).all()}
                for item in items:
                    cve_id = str(item.get("cve_id") or "").upper()
                    if cve_id and cve_id in known:
                        continue
                    if ingest_payload(db, source, payload=item):
                        if cve_id:
                            known.add(cve_id)
                source.last_error = None
                source.last_event_at = datetime.now(timezone.utc)
            except Exception as exc:
                log.exception("API feed %s failed", source.name)
                source.last_error = str(exc)
        db.commit()
        _touch_repositories(db)
    finally:
        db.close()


def poll_exchange() -> None:
    db = SessionLocal()
    try:
        sources = (
            db.query(InputSource)
            .filter(InputSource.enabled.is_(True), InputSource.source_type == "email")
            .all()
        )
        if not sources:
            return
        messages = ExchangeClient().poll_unread()
        for source in sources:
            for message in messages:
                ingest_payload(
                    db,
                    source,
                    payload=message,
                    raw_text=f"{message.get('subject','')}\n{message.get('body','')}",
                )
            source.last_event_at = datetime.now(timezone.utc)
        db.commit()
    except Exception:
        log.exception("Exchange poll failed")
    finally:
        db.close()


def _normalize_feed_items(payload) -> list[dict]:
    """Unwrap NVD 2.0 envelopes and other common feed shapes into ingest dicts."""
    if isinstance(payload, list):
        return [item if isinstance(item, dict) else {"data": item} for item in payload]
    if not isinstance(payload, dict):
        return [{"data": payload}]
    if "vulnerabilities" in payload:
        items = []
        for row in payload.get("vulnerabilities") or []:
            cve = row.get("cve") or {}
            descriptions = cve.get("descriptions") or []
            english = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
            cve_id = cve.get("id")
            published = cve.get("published")
            if cve_id and not allow_cve(cve_id, parse_published(published)):
                continue
            items.append(
                {
                    "cve_id": cve_id,
                    "summary": english,
                    "vendor": None,
                    "product": None,
                    "published": published,
                }
            )
        return items
    if "data" in payload and isinstance(payload["data"], list):
        return [row if isinstance(row, dict) else {"data": row} for row in payload["data"]]
    return [payload]


def _feed_headers(source: InputSource) -> dict[str, str]:
    token = (source.config or {}).get("token")
    headers = {"User-Agent": "EVulnTasker/1.0", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def poll_smb() -> None:
    db = SessionLocal()
    try:
        sources = db.query(InputSource).filter(InputSource.enabled.is_(True)).all()
        smb_sources = [s for s in sources if getattr(s, "source_type", getattr(s, "source_type", "")) == "smb"]
        if not smb_sources:
            return
        from app.api.settings.feeds import pull_smb_files

        for source in smb_sources:
            try:
                pull_smb_files(db, source)
            except Exception as exc:
                log.exception("SMB poll failed for %s", source.name)
                from app.api.settings.common import record_source_error

                record_source_error(source, str(exc))
        db.commit()
    finally:
        db.close()


def _poll_interval(source: InputSource, kind: str) -> int:
    try:
        return max(30, int((source.config or {}).get("poll_seconds") or POLL_DEFAULTS.get(kind, 300)))
    except (TypeError, ValueError):
        return POLL_DEFAULTS.get(kind, 300)


def _is_due(source: InputSource, kind: str) -> bool:
    interval = _poll_interval(source, kind)
    raw = (source.config or {}).get("last_poll_at")
    if not raw:
        return True
    try:
        last = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    return datetime.now(timezone.utc) - last >= timedelta(seconds=interval)


def _mark_polled(source: InputSource) -> None:
    from sqlalchemy.orm.attributes import flag_modified

    cfg = dict(source.config or {})
    cfg["last_poll_at"] = datetime.now(timezone.utc).isoformat()
    source.config = cfg
    flag_modified(source, "config")


def _poll_kind(kind: str, pull) -> None:
    db = SessionLocal()
    try:
        sources = db.query(InputSource).filter(InputSource.enabled.is_(True)).all()
        matched = [s for s in sources if getattr(s, "source_type", "") == kind]
        for source in matched:
            if not _is_due(source, kind):
                continue
            try:
                pull(db, source)
                _mark_polled(source)
            except Exception as exc:
                log.exception("%s poll failed for %s", kind, source.name)
                from app.api.settings.common import record_source_error

                record_source_error(source, str(exc))
        db.commit()
    finally:
        db.close()


def poll_local() -> None:
    from app.api.settings.feeds import pull_local_files

    _poll_kind("local", pull_local_files)


def poll_outlook() -> None:
    from app.api.settings.feeds import pull_outlook

    _poll_kind("outlook", pull_outlook)


def poll_web_api() -> None:
    from app.api.settings.feeds import pull_web_api

    _poll_kind("web_api", pull_web_api)


def poll_inventory() -> None:
    from app.services.inventory_sync import maybe_sync_inventory

    maybe_sync_inventory()


def _touch_repositories(db) -> None:
    """Update NVD/EPSS repository sync timestamps after a successful poll cycle."""
    repos = db.query(VulnerabilityRepository).filter(VulnerabilityRepository.enabled.is_(True)).all()
    now = datetime.now(timezone.utc)
    for repo in repos:
        repo.last_sync_at = now
        repo.sync_status = "ok"
    db.commit()
