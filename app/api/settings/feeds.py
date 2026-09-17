"""Feed source settings: SMB, local, Outlook, ATOM feeds."""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.settings.common import (
    apply_display_name,
    get_or_create_source,
    public_source,
    record_source_error,
    save_env,
    save_source_cfg,
)
from app.db.session import get_db
from app.models.source import InputSource
from app.services import file_ingest
from app.services.ingestion import ingest_payload, skip_unchanged_ingest_file
from app.utils.cve import extract_cves

router = APIRouter()


class SmbLocationIn(BaseModel):
    name: str = ""
    server: str = ""
    share: str = ""
    path: str = ""


class SmbIn(BaseModel):
    enabled: bool = False
    name: str = ""
    locations: list[SmbLocationIn] = Field(default_factory=list)
    server: str = ""
    share: str = ""
    path: str = ""
    domain: str = ""
    username: str = ""
    password: str = ""
    poll_seconds: int = Field(default=300, ge=30, le=86400)


class LocalIn(BaseModel):
    enabled: bool = False
    name: str = ""
    path: str = ""
    poll_seconds: int = Field(default=60, ge=15, le=86400)


class LocalTestIn(BaseModel):
    path: str = ""


class OutlookIn(BaseModel):
    enabled: bool = False
    name: str = ""
    server: str = ""
    domain: str = ""
    username: str = ""
    password: str = ""
    email: str = ""
    folder: str = "Inbox"
    poll_seconds: int = Field(default=120, ge=30, le=86400)


class AtomFeedIn(BaseModel):
    url: str = ""
    name: str = ""
    token: str = ""
    feed_type: str = ""


class WebApiIn(BaseModel):
    enabled: bool = False
    name: str = ""
    feeds: list[AtomFeedIn] = Field(default_factory=list)
    url: str = ""
    token: str = ""
    poll_seconds: int = Field(default=3600, ge=60, le=86400)
    intel_start_date: str | None = None


@router.put("/settings/smb")
def save_smb(body: SmbIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    from app.integrations.smb import normalize_locations

    source = get_or_create_source(db, "smb")
    apply_display_name(db, source, body.name, "smb")
    cfg = dict(source.config or {})
    incoming = [
        {"name": row.name.strip(), "server": row.server.strip(), "share": row.share.strip(), "path": row.path.strip()}
        for row in body.locations
    ]
    if not incoming and body.server.strip() and body.share.strip():
        incoming = [
            {
                "name": "",
                "server": body.server.strip(),
                "share": body.share.strip(),
                "path": body.path.strip(),
            }
        ]
    locations = normalize_locations({"locations": incoming})
    cfg["locations"] = locations
    first = locations[0] if locations else {}
    cfg["server"] = first.get("server") or ""
    cfg["share"] = first.get("share") or ""
    cfg["path"] = first.get("path") or ""
    cfg["domain"] = body.domain.strip()
    cfg["username"] = body.username.strip()
    cfg["poll_seconds"] = body.poll_seconds
    if body.password:
        cfg["password"] = body.password
    source.config = cfg
    source.last_error = None
    db.commit()
    db.refresh(source)
    from app.services.repo_catalog import sync_source_repositories

    sync_source_repositories(db)
    return {"smb": public_source(source)}


@router.put("/settings/local")
def save_local(body: LocalIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    source = get_or_create_source(db, "local")
    apply_display_name(db, source, body.name, "local")
    save_source_cfg(source, body, ["path", "poll_seconds"])
    db.commit()
    db.refresh(source)
    from app.services.repo_catalog import sync_source_repositories

    sync_source_repositories(db)
    return {"local": public_source(source)}


@router.put("/settings/outlook")
def save_outlook(body: OutlookIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    source = get_or_create_source(db, "outlook")
    apply_display_name(db, source, body.name, "outlook")
    save_source_cfg(source, body, ["server", "domain", "username", "password", "email", "folder", "poll_seconds"])
    db.commit()
    db.refresh(source)
    from app.services.repo_catalog import sync_source_repositories

    sync_source_repositories(db)
    return {"outlook": public_source(source)}


@router.put("/settings/web-api")
def save_web_api(body: WebApiIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    from app.services.atom_feed import merge_preserved_tokens, normalize_feeds

    source = get_or_create_source(db, "web_api")
    cfg = dict(source.config or {})
    incoming = [
        {
            "url": row.url.strip(),
            "name": row.name.strip(),
            "token": row.token.strip(),
            "feed_type": row.feed_type.strip(),
        }
        for row in body.feeds
    ]
    if not any(row["url"] for row in incoming) and body.url.strip():
        incoming = [{"url": body.url.strip(), "name": "", "token": body.token.strip()}]
    feeds = merge_preserved_tokens(normalize_feeds({"feeds": incoming}), cfg)
    apply_display_name(db, source, body.name, "web_api")
    cfg["feeds"] = feeds
    cfg["url"] = feeds[0]["url"] if feeds else ""
    cfg["poll_seconds"] = body.poll_seconds
    if body.token.strip():
        cfg["token"] = body.token.strip()
    source.config = cfg
    source.last_error = None
    from app.services.repo_catalog import apply_lookup_feed_edits, sync_atom_channel_enabled, sync_atom_repositories

    sync_atom_repositories(db, source=source, commit=False)
    apply_lookup_feed_edits(db, feeds)
    sync_atom_channel_enabled(db)
    db.commit()
    db.refresh(source)
    if body.intel_start_date is not None:
        start = body.intel_start_date.strip()[:10]
        save_env({"INTEL_START_DATE": start or "2024-01-01"})
    return {"web_api": public_source(source)}


@router.post("/settings/web-api/restore")
def restore_web_api(db: Session = Depends(get_db)) -> dict[str, Any]:
    from app.services.repo_catalog import restore_default_atom_feeds

    source = restore_default_atom_feeds(db)
    return {"ok": True, "web_api": public_source(source)}


@router.post("/settings/smb/test")
def test_smb(db: Session = Depends(get_db)) -> dict[str, Any]:
    source = get_or_create_source(db, "smb")
    try:
        from app.integrations.smb import test_locations

        result = test_locations(source.config or {})
        record_source_error(
            source,
            None if result.get("ok") else "; ".join(
                row.get("error") or "" for row in result.get("locations") or [] if row.get("error")
            ),
        )
        db.commit()
        return result
    except Exception as exc:
        record_source_error(source, str(exc))
        db.commit()
        raise HTTPException(400, f"SMB connection failed: {exc}") from exc


@router.post("/settings/local/test")
def test_local(body: LocalTestIn = Body(default_factory=LocalTestIn), db: Session = Depends(get_db)) -> dict[str, Any]:
    source = get_or_create_source(db, "local")
    raw = (body.path or "").strip() or (source.config or {}).get("path") or ""
    try:
        path = file_ingest.local_folder(raw)
        names: list[str] = []
        total = 0
        for entry in path.iterdir():
            if not entry.is_file():
                continue
            total += 1
            if len(names) < 20:
                names.append(entry.name)
    except ValueError as exc:
        record_source_error(source, str(exc))
        db.commit()
        raise HTTPException(400, str(exc)) from exc
    except OSError as exc:
        record_source_error(source, str(exc))
        db.commit()
        raise HTTPException(400, f"Cannot read folder: {exc}") from exc
    record_source_error(source, None)
    db.commit()
    return {
        "ok": True,
        "path": str(path),
        "files": total,
        "sample": [{"name": n} for n in names],
    }


@router.post("/settings/outlook/test")
def test_outlook(db: Session = Depends(get_db)) -> dict[str, Any]:
    source = get_or_create_source(db, "outlook")
    try:
        from app.integrations.exchange import ExchangeClient

        client = ExchangeClient(source.config or {})
        if not client.configured():
            raise ValueError("Exchange server and username are required")
        client._connect()
        source.last_error = None
        db.commit()
        return {"ok": True, "mailbox": (source.config or {}).get("email") or (source.config or {}).get("username")}
    except Exception as exc:
        record_source_error(source, str(exc))
        db.commit()
        raise HTTPException(400, f"Exchange connection failed: {exc}") from exc


@router.post("/settings/web-api/test")
def test_web_api(db: Session = Depends(get_db)) -> dict[str, Any]:
    from app.services.atom_feed import entry_cves, feed_headers, normalize_feeds, parse_feed
    from app.services.repo_catalog import is_lookup_feed

    source = get_or_create_source(db, "web_api")
    feeds = normalize_feeds(source.config or {})
    if not feeds:
        raise HTTPException(400, "Add at least one ATOM feed URL")
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    for feed in feeds:
        if is_lookup_feed(feed, feed["url"]):
            results.append(
                {
                    "url": feed["url"],
                    "name": feed.get("name") or "",
                    "format": feed.get("feed_type") or "lookup",
                    "entries": 0,
                    "cves": 0,
                    "sample": [],
                    "skipped": "lookup",
                }
            )
            continue
        try:
            response = httpx.get(feed["url"], timeout=20.0, headers=feed_headers(feed.get("token") or ""))
            response.raise_for_status()
            parsed = parse_feed(response.text)
            cves = sorted({cve for entry in parsed["entries"] for cve in entry_cves(entry)})
            results.append(
                {
                    "url": feed["url"],
                    "name": feed.get("name") or parsed.get("title") or "",
                    "format": parsed["format"],
                    "entries": len(parsed["entries"]),
                    "cves": len(cves),
                    "sample": cves[:8],
                }
            )
        except Exception as exc:
            errors.append(f"{feed['url']}: {exc}")
            results.append({"url": feed["url"], "error": str(exc)})
    if errors and not any("format" in row for row in results):
        record_source_error(source, "; ".join(errors))
        db.commit()
        raise HTTPException(400, f"ATOM feed request failed: {errors[0]}")
    record_source_error(source, "; ".join(errors) if errors else None)
    db.commit()
    return {"ok": not errors, "feeds": results}


def _stamp_if_done(seen: dict[str, str], key: str, stamp: str, text: str, created: bool) -> None:
    if created or not extract_cves(text):
        seen[key] = stamp


def pull_smb_files(db: Session, source: InputSource) -> int:
    from app.integrations.smb import list_text_files, location_config, normalize_locations, read_text_file

    cfg = dict(source.config or {})
    locations = normalize_locations(cfg)
    if not locations:
        raise ValueError("Add at least one SMB location (server and share)")
    seen = dict(cfg.get("seen") or {})
    ingested = 0
    errors: list[str] = []
    for loc in locations:
        loc_cfg = location_config(cfg, loc)
        label = loc.get("name") or f"{loc['server']}\\{loc['share']}"
        try:
            files = list_text_files(loc_cfg)
        except Exception as exc:
            errors.append(f"{label}: {exc}")
            continue
        for info in files:
            stamp_key = info["path"]
            stamp = f"{info['size']}:{info['mtime']}"
            filename = info["name"]
            if skip_unchanged_ingest_file(db, source.id, filename, seen.get(stamp_key), stamp):
                continue
            text = read_text_file(info["path"], loc_cfg)
            created = bool(
                file_ingest.ingest_text(
                    db,
                    source,
                    text,
                    filename=filename,
                    extra={
                        "location": label,
                        "smb_server": loc.get("server") or "",
                        "smb_share": loc.get("share") or "",
                        "smb_path": loc.get("path") or "",
                        "file_path": info.get("path") or "",
                    },
                )
            )
            if created:
                ingested += 1
            _stamp_if_done(seen, stamp_key, stamp, text, created)
    cfg["locations"] = locations
    cfg["seen"] = seen
    source.config = cfg
    if errors and ingested == 0:
        record_source_error(source, "; ".join(errors))
        db.commit()
        raise ValueError("; ".join(errors))
    record_source_error(source, "; ".join(errors) if errors else None)
    db.commit()
    return ingested


def pull_local_files(db: Session, source: InputSource) -> int:
    cfg = dict(source.config or {})
    folder = file_ingest.local_folder(cfg.get("path") or "")
    seen = dict(cfg.get("seen") or {})
    ingested = 0
    for path in sorted(folder.iterdir()):
        if not path.is_file() or not file_ingest.is_readable(path):
            continue
        stamp = f"{path.stat().st_size}:{int(path.stat().st_mtime)}"
        if skip_unchanged_ingest_file(db, source.id, path.name, seen.get(path.name), stamp):
            continue
        text = file_ingest.read_as_text(path)
        if text is None:
            continue
        created = bool(file_ingest.ingest_text(db, source, text, filename=path.name))
        if created:
            ingested += 1
        _stamp_if_done(seen, path.name, stamp, text, created)
    cfg["seen"] = seen
    source.config = cfg
    source.last_error = None
    db.commit()
    return ingested


def pull_outlook(db: Session, source: InputSource) -> int:
    from app.integrations.exchange import ExchangeClient

    client = ExchangeClient(source.config or {})
    if not client.configured():
        raise ValueError("Exchange server and username are required")
    messages = client.poll_unread()
    count = 0
    for message in messages:
        text = f"{message.get('subject', '')}\n{message.get('body', '')}"
        if ingest_payload(db, source, payload=message, raw_text=text):
            count += 1
    record_source_error(source, None)
    db.commit()
    return count


def pull_web_api(
    db: Session,
    source: InputSource,
    only_url: str | None = None,
    *,
    include_disabled: bool | None = None,
) -> int:
    from app.services.atom_feed import (
        entry_cves,
        entry_text,
        feed_headers,
        normalize_feeds,
        parse_feed,
    )
    from app.services.repo_catalog import atom_feed_enabled, is_lookup_feed, mark_atom_synced

    cfg = dict(source.config or {})
    feeds = normalize_feeds(cfg)
    if only_url:
        feeds = [feed for feed in feeds if feed["url"] == only_url]
        if not feeds:
            raise ValueError("That ATOM feed is no longer in Settings → Feeds.")
        if include_disabled is None:
            include_disabled = True
    elif not feeds:
        raise ValueError("Add at least one ATOM feed URL")
    ingested = 0
    errors: list[str] = []
    for feed in feeds:
        url = feed["url"]
        if is_lookup_feed(feed, url):
            continue
        if not include_disabled and not atom_feed_enabled(db, url):
            continue
        feed_ingested = 0
        try:
            response = httpx.get(url, timeout=30.0, headers=feed_headers(feed.get("token") or ""))
            response.raise_for_status()
            parsed = parse_feed(response.text)
        except Exception as exc:
            errors.append(f"{url}: {exc}")
            mark_atom_synced(db, url, ok=False, error=str(exc))
            continue
        for entry in parsed["entries"]:
            raw = entry_text(entry)
            cves = entry_cves(entry)
            if not cves:
                continue
            payload = {
                "cves": cves,
                "cve_id": cves[0],
                "title": entry.get("title") or "",
                "summary": entry.get("summary") or entry.get("content") or "",
                "published": entry.get("updated") or "",
                "link": entry.get("link") or "",
                "feed_url": url,
                "feed_name": feed.get("name") or parsed.get("title") or "",
                "feed_type": feed.get("feed_type") or "",
                "entry_id": entry.get("id") or "",
            }
            if ingest_payload(db, source, payload=payload, raw_text=raw):
                ingested += 1
                feed_ingested += 1
        mark_atom_synced(db, url, ok=True, ingested=feed_ingested)
    if errors and ingested == 0:
        record_source_error(source, "; ".join(errors))
        db.commit()
        raise ValueError("; ".join(errors))
    record_source_error(source, "; ".join(errors) if errors else None)
    db.commit()
    return ingested


@router.post("/settings/{kind}/sync")
def sync_kind(kind: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    from app.api.settings.common import SOURCES

    if kind not in SOURCES:
        raise HTTPException(404, "Unknown source kind")
    source = get_or_create_source(db, kind)
    try:
        if kind == "smb":
            count = pull_smb_files(db, source)
        elif kind == "local":
            count = pull_local_files(db, source)
        elif kind == "outlook":
            count = pull_outlook(db, source)
        else:
            count = pull_web_api(db, source)
        return {"ok": True, "ingested": count}
    except Exception as exc:
        record_source_error(source, str(exc))
        db.commit()
        raise HTTPException(400, f"Sync failed: {exc}") from exc
