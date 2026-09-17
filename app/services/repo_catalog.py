"""Feed catalog rows shown on Input Sources: intel lookups + operator ATOM/local feeds."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.models.repository import VulnerabilityRepository
from app.models.source import InputSource

ATOM_TYPE = "atom"
PLACEHOLDER_NAMES = {"internal scans"}
PLACEHOLDER_TYPES = {"internal"}

LOOKUP_FEED_TYPES = ("nvd", "epss")

# Catalog interfaces from Vulnerability Repositories, copied into
# Settings → Feeds → ATOM feeds (lookups are listed there too, but not polled as ATOM).
DEFAULT_ATOM_FEEDS = [
    dict(
        name="NVD",
        endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0",
        feed_type="nvd",
        notes="National Vulnerability Database 2.0. Lookup during enrichment; listed here so you can edit the URL.",
    ),
    dict(
        name="FIRST EPSS",
        endpoint="https://api.first.org/data/v1/epss",
        feed_type="epss",
        notes="FIRST EPSS probabilities. Lookup during enrichment; listed here so you can edit the URL.",
    ),
    dict(
        name="CISA Advisories",
        endpoint="https://www.cisa.gov/cybersecurity-advisories/all.xml",
        feed_type="atom",
        notes="US CISA cybersecurity advisories (ATOM). Edit or remove in Settings → Feeds.",
    ),
    dict(
        name="Ubuntu Security Notices",
        endpoint="https://ubuntu.com/security/notices/rss.xml",
        feed_type="atom",
        notes="Ubuntu USN RSS — Linux package CVEs. Edit or remove in Settings → Feeds.",
    ),
    dict(
        name="Microsoft MSRC",
        endpoint="https://api.msrc.microsoft.com/update-guide/rss",
        feed_type="atom",
        notes="Microsoft Security Response Center update guide (RSS). Edit or remove in Settings → Feeds.",
    ),
    dict(
        name="Exploit-DB",
        endpoint="https://www.exploit-db.com/rss.xml",
        feed_type="atom",
        notes="Public exploit references (RSS). Edit or remove in Settings → Feeds.",
    ),
]
EXPLOITDB_RSS = "https://www.exploit-db.com/rss.xml"


def _cfg(row: VulnerabilityRepository) -> dict[str, Any]:
    blob = row.config if isinstance(row.config, dict) else {}
    return dict(blob)


def _unique_name(db: Session, desired: str, exclude_id: int | None = None) -> str:
    name = desired or "ATOM feed"
    suffix = 2
    while True:
        query = db.query(VulnerabilityRepository).filter(VulnerabilityRepository.name == name)
        if exclude_id is not None:
            query = query.filter(VulnerabilityRepository.id != exclude_id)
        if query.first() is None:
            return name
        name = f"{desired} {suffix}"
        suffix += 1


def _display_name(feed: dict[str, str]) -> str:
    name = str(feed.get("name") or "").strip()
    if name:
        return name
    parsed = urlparse(feed.get("url") or "")
    return parsed.netloc or (feed.get("url") or "ATOM feed")


def _atom_url(row: VulnerabilityRepository) -> str:
    return str(_cfg(row).get("url") or row.endpoint or "").strip()


def purge_placeholder_repos(db: Session) -> int:
    """Remove leftover demo rows such as Internal Scans (never a real scanner)."""
    removed = 0
    rows = db.query(VulnerabilityRepository).all()
    for row in rows:
        name = (row.name or "").strip().lower()
        endpoint = (row.endpoint or "").lower()
        if (
            row.feed_type in PLACEHOLDER_TYPES
            or name in PLACEHOLDER_NAMES
            or "scanner.internal.example" in endpoint
        ):
            db.delete(row)
            removed += 1
    if removed:
        db.commit()
    return removed


def atom_source(db: Session) -> InputSource | None:
    return (
        db.query(InputSource)
        .filter(InputSource.source_type == "web_api")
        .order_by(InputSource.id.asc())
        .first()
    )


def _migrate_exploitdb_rows(db: Session) -> bool:
    """Turn the old metadata-only Exploit-DB website row into the RSS ingest feed."""
    changed = False
    rows = (
        db.query(VulnerabilityRepository)
        .filter(VulnerabilityRepository.feed_type == "exploitdb")
        .all()
    )
    for row in rows:
        row.feed_type = ATOM_TYPE
        row.endpoint = EXPLOITDB_RSS
        row.enabled = True
        row.notes = "Public exploit references (RSS). Edit or remove in Settings → Feeds."
        cfg = _cfg(row)
        cfg["atom_managed"] = True
        cfg["url"] = EXPLOITDB_RSS
        cfg["built_in"] = True
        row.config = cfg
        flag_modified(row, "config")
        changed = True
    return changed


def _feed_type(feed: dict[str, Any], url: str = "") -> str:
    kind = str(feed.get("feed_type") or "").strip().lower()
    if kind in LOOKUP_FEED_TYPES or kind == ATOM_TYPE:
        return kind
    target = (url or str(feed.get("url") or "") or "").lower()
    name = str(feed.get("name") or "").strip().lower()
    if "nvd.nist.gov" in target or name == "nvd":
        return "nvd"
    if "api.first.org" in target or "epss" in name:
        return "epss"
    return ATOM_TYPE


def _lookup_urls(db: Session) -> set[str]:
    urls = {spec["endpoint"] for spec in DEFAULT_ATOM_FEEDS if spec.get("feed_type") in LOOKUP_FEED_TYPES}
    rows = (
        db.query(VulnerabilityRepository)
        .filter(VulnerabilityRepository.feed_type.in_(LOOKUP_FEED_TYPES))
        .all()
    )
    for row in rows:
        if row.endpoint:
            urls.add(row.endpoint.strip())
    return urls


def _dedupe_atom_repos(db: Session) -> bool:
    """Keep one ATOM row per URL (drops leftover Exploit-DB 2 duplicates)."""
    rows = (
        db.query(VulnerabilityRepository)
        .filter(VulnerabilityRepository.feed_type == ATOM_TYPE)
        .order_by(VulnerabilityRepository.id.asc())
        .all()
    )
    seen: dict[str, VulnerabilityRepository] = {}
    removed = False
    for row in rows:
        url = _atom_url(row)
        if not url:
            continue
        keep = seen.get(url)
        if keep is None:
            seen[url] = row
            continue
        # Prefer the original catalog name over "Exploit-DB 2".
        if keep.name.endswith(" 2") and not row.name.endswith(" 2"):
            db.delete(keep)
            seen[url] = row
        else:
            db.delete(row)
        removed = True
    return removed


def _merge_default_atom_feeds(
    existing: list[dict[str, str]],
    *,
    kinds: tuple[str, ...] | None = None,
) -> list[dict[str, str]]:
    have = {str(row.get("url") or "") for row in existing}
    extra: list[dict[str, str]] = []
    for spec in DEFAULT_ATOM_FEEDS:
        kind = spec.get("feed_type") or ATOM_TYPE
        if kinds is not None and kind not in kinds:
            continue
        url = spec["endpoint"]
        if url in have:
            continue
        extra.append(
            {
                "url": url,
                "name": spec["name"],
                "token": "",
                "feed_type": kind,
            }
        )
        have.add(url)
    lookups = [row for row in extra if row.get("feed_type") in LOOKUP_FEED_TYPES]
    others = [row for row in extra if row.get("feed_type") not in LOOKUP_FEED_TYPES]
    return lookups + [dict(row) for row in existing] + others


def _write_atom_settings(source: InputSource, feeds: list[dict[str, str]]) -> None:
    cfg = dict(source.config or {})
    cfg["feeds"] = feeds
    cfg["url"] = feeds[0]["url"] if feeds else ""
    source.config = cfg
    flag_modified(source, "config")


def ensure_atom_feeds(db: Session, source: InputSource | None = None) -> InputSource:
    """Copy the Repositories ATOM catalog into Settings → Feeds on first install.

    Does not resurrect feeds the operator deleted after ATOM_FEEDS_SEEDED=true.
    """
    from app.api.settings.common import get_or_create_source, save_env
    from app.config import get_settings
    from app.services.atom_feed import normalize_feeds

    source = source if source is not None else atom_source(db)
    if source is None:
        source = get_or_create_source(db, "web_api")

    _migrate_exploitdb_rows(db)
    _dedupe_atom_repos(db)
    settings = get_settings()
    feeds = normalize_feeds(source.config or {})
    changed = False
    if not settings.atom_feeds_seeded:
        feeds = _merge_default_atom_feeds(feeds)
        changed = True
        save_env({"ATOM_FEEDS_SEEDED": "true", "ATOM_LOOKUPS_SEEDED": "true"})
    elif not settings.atom_lookups_seeded:
        feeds = _merge_default_atom_feeds(feeds, kinds=LOOKUP_FEED_TYPES)
        changed = True
        save_env({"ATOM_LOOKUPS_SEEDED": "true"})
    if changed:
        _write_atom_settings(source, feeds)
    sync_atom_repositories(db, source=source, commit=False)
    sync_atom_channel_enabled(db, align_legacy=True)
    db.commit()
    db.refresh(source)
    return source


def restore_default_atom_feeds(db: Session) -> InputSource:
    """Re-add missing built-in ATOM URLs. Leaves feeds the operator still has."""
    from app.services.atom_feed import normalize_feeds

    source = ensure_atom_feeds(db)
    feeds = _merge_default_atom_feeds(normalize_feeds(source.config or {}))
    _write_atom_settings(source, feeds)
    sync_atom_repositories(db, source=source, commit=False)
    sync_atom_channel_enabled(db)
    db.commit()
    db.refresh(source)
    return source


def is_lookup_feed(feed: dict[str, Any] | None, url: str = "") -> bool:
    return _feed_type(feed or {}, url) in LOOKUP_FEED_TYPES


def atom_feed_enabled(db: Session, url: str) -> bool:
    row = (
        db.query(VulnerabilityRepository)
        .filter(
            VulnerabilityRepository.feed_type == ATOM_TYPE,
            VulnerabilityRepository.endpoint == url,
        )
        .first()
    )
    if row is None:
        return False
    return bool(row.enabled)


def _atom_rows(db: Session) -> list[VulnerabilityRepository]:
    return (
        db.query(VulnerabilityRepository)
        .filter(VulnerabilityRepository.feed_type == ATOM_TYPE)
        .all()
    )


def sync_atom_channel_enabled(db: Session, *, align_legacy: bool = False) -> None:
    """web_api.enabled follows per-feed Enable on Vulnerability Repositories.

    align_legacy: if the ATOM channel was off, per-feed Enable was never the
    poll switch — pause those rows so upgrade does not start polling.
    """
    source = atom_source(db)
    rows = _atom_rows(db)
    if source is None:
        return
    if align_legacy and not source.enabled:
        for row in rows:
            if row.enabled:
                row.enabled = False
    source.enabled = any(row.enabled for row in rows)


def set_all_atom_feeds_enabled(db: Session, enabled: bool) -> None:
    for row in _atom_rows(db):
        row.enabled = bool(enabled)
    source = atom_source(db)
    if source is not None:
        source.enabled = bool(enabled) and bool(_atom_rows(db))


def sync_atom_repositories(db: Session, source: InputSource | None = None, commit: bool = True) -> None:
    """Mirror Settings → Feeds → ATOM URLs onto Vulnerability Repositories."""
    from app.services.atom_feed import normalize_feeds

    source = source if source is not None else atom_source(db)
    feeds = normalize_feeds(source.config if source else {})
    existing = (
        db.query(VulnerabilityRepository)
        .filter(VulnerabilityRepository.feed_type == ATOM_TYPE)
        .all()
    )
    by_url: dict[str, VulnerabilityRepository] = {}
    for row in existing:
        url = _atom_url(row)
        if url:
            by_url[url] = row

    keep: set[str] = set()
    changed = False
    lookup_urls = _lookup_urls(db)
    for feed in feeds:
        url = feed["url"]
        keep.add(url)
        if _feed_type(feed, url) in LOOKUP_FEED_TYPES or url in lookup_urls:
            continue
        row = by_url.get(url)
        if row is None:
            row = VulnerabilityRepository(
                name=_unique_name(db, _display_name(feed)),
                feed_type=ATOM_TYPE,
                endpoint=url,
                enabled=False,
                sync_status="idle",
                notes="ATOM/RSS ingest feed from Settings → Feeds.",
                config={"atom_managed": True, "url": url},
            )
            db.add(row)
            db.flush()
            changed = True
        else:
            desired = _display_name(feed)
            if row.name != desired:
                row.name = _unique_name(db, desired, exclude_id=row.id)
                changed = True
            if row.endpoint != url:
                row.endpoint = url
                changed = True
            cfg = _cfg(row)
            if not cfg.get("atom_managed") or cfg.get("url") != url:
                cfg["atom_managed"] = True
                cfg["url"] = url
                row.config = cfg
                flag_modified(row, "config")
                changed = True

    for row in existing:
        url = _atom_url(row)
        if url in lookup_urls or url not in keep:
            db.delete(row)
            changed = True

    if commit and changed:
        db.commit()


def apply_lookup_feed_edits(db: Session, feeds: list[dict[str, Any]]) -> None:
    """If NVD/EPSS URLs were edited in Settings → ATOM feeds, keep the lookup rows in sync."""
    from app.api.settings.common import save_env

    updates: dict[str, str] = {}
    for feed in feeds:
        url = str(feed.get("url") or "").strip()
        kind = _feed_type(feed, url)
        if kind not in LOOKUP_FEED_TYPES or not url:
            continue
        row = (
            db.query(VulnerabilityRepository)
            .filter(VulnerabilityRepository.feed_type == kind)
            .order_by(VulnerabilityRepository.id.asc())
            .first()
        )
        if row is None:
            continue
        if row.endpoint != url:
            row.endpoint = url
        name = str(feed.get("name") or "").strip()
        if name and row.name != name:
            row.name = _unique_name(db, name, exclude_id=row.id)
        if kind == "nvd":
            updates["NVD_API_BASE"] = url
        elif kind == "epss":
            updates["EPSS_API_BASE"] = url
    if updates:
        save_env(updates)


def mark_atom_synced(
    db: Session,
    url: str,
    *,
    ok: bool,
    ingested: int = 0,
    error: str | None = None,
) -> None:
    row = (
        db.query(VulnerabilityRepository)
        .filter(
            VulnerabilityRepository.feed_type == ATOM_TYPE,
            VulnerabilityRepository.endpoint == url,
        )
        .first()
    )
    if row is None:
        return
    row.last_sync_at = datetime.now(timezone.utc)
    row.sync_status = "ok" if ok else "error"
    row.last_error = error
    if ingested:
        row.raw_count = int(row.raw_count or 0) + ingested


SOURCE_REPO_TYPES = ("local", "smb", "outlook", "inline")
_TYPE_RANK = {
    "nvd": 0,
    "epss": 1,
    "local": 2,
    "smb": 3,
    "outlook": 4,
    "inline": 5,
    "atom": 6,
}


def _join_endpoint(*parts: str) -> str:
    return " · ".join(part for part in parts if part)


def _source_status(source: InputSource) -> tuple[str, str | None]:
    err = (getattr(source, "last_error", None) or "").strip() or None
    if err:
        return "error", err
    if getattr(source, "last_event_at", None):
        return "ok", None
    return "idle", None


def _source_specs(source: InputSource) -> list[dict[str, Any]]:
    cfg = source.config if isinstance(source.config, dict) else {}
    kind = (source.source_type or "").strip().lower()
    status, error = _source_status(source)
    base = {
        "source_id": source.id,
        "source_type": kind,
        "enabled": bool(source.enabled),
        "last_sync_at": getattr(source, "last_event_at", None),
        "raw_count": int(getattr(source, "event_count", 0) or 0),
        "sync_status": status,
        "last_error": error,
    }
    if kind == "local":
        path = str(cfg.get("path") or "").strip()
        if not path:
            return []
        return [
            {
                **base,
                "name": (source.name or "").strip() or "Local folder",
                "feed_type": "local",
                "endpoint": path,
                "location_key": "folder",
                "notes": "Folder on this EVulnTasker host. Edit in Settings → Feeds → Local folder.",
            }
        ]
    if kind == "smb":
        from app.integrations.smb import normalize_locations, unc_path

        specs: list[dict[str, Any]] = []
        for loc in normalize_locations(cfg):
            endpoint = unc_path(loc["server"], loc["share"], loc.get("path") or "")
            loc_name = str(loc.get("name") or "").strip()
            key = f"{loc['server']}|{loc['share']}|{loc.get('path') or ''}".lower()
            specs.append(
                {
                    **base,
                    "name": loc_name or (source.name or "").strip() or "SMB share",
                    "feed_type": "smb",
                    "endpoint": endpoint,
                    "location_key": key,
                    "notes": "SMB/CIFS location. Edit in Settings → Feeds → SMB.",
                }
            )
        return specs
    if kind == "outlook":
        server = str(cfg.get("server") or "").strip()
        folder = str(cfg.get("folder") or "").strip() or "Inbox"
        email = str(cfg.get("email") or "").strip()
        if not server and not email:
            return []
        return [
            {
                **base,
                "name": (source.name or "").strip() or "Outlook / Exchange",
                "feed_type": "outlook",
                "endpoint": _join_endpoint(server, folder, email),
                "location_key": "mailbox",
                "notes": "On-prem Exchange mailbox. Edit in Settings → Feeds → Outlook / Exchange.",
            }
        ]
    if kind == "inline":
        return [
            {
                **base,
                "name": (source.name or "").strip() or "Inline CVE",
                "feed_type": "inline",
                "endpoint": "Input Sources · Inline CVE",
                "location_key": "form",
                "notes": "CVE IDs entered by an operator. Open Input Sources to submit one.",
            }
        ]
    return []


def _source_repo_key(row: VulnerabilityRepository) -> tuple[str, str, str] | None:
    cfg = _cfg(row)
    if not cfg.get("source_managed"):
        return None
    return (
        str(cfg.get("source_type") or row.feed_type or ""),
        str(cfg.get("source_id") or ""),
        str(cfg.get("location_key") or ""),
    )


def sync_source_repositories(db: Session, commit: bool = True) -> None:
    """Mirror Local / SMB / Exchange / Inline settings onto Vulnerability Repositories."""
    specs: list[dict[str, Any]] = []
    sources = (
        db.query(InputSource)
        .filter(InputSource.source_type.in_(SOURCE_REPO_TYPES))
        .order_by(InputSource.id.asc())
        .all()
    )
    for source in sources:
        specs.extend(_source_specs(source))

    existing = db.query(VulnerabilityRepository).all()
    by_key: dict[tuple[str, str, str], VulnerabilityRepository] = {}
    managed: list[VulnerabilityRepository] = []
    for row in existing:
        key = _source_repo_key(row)
        if key is None:
            continue
        managed.append(row)
        by_key[key] = row

    keep: set[tuple[str, str, str]] = set()
    changed = False
    for spec in specs:
        key = (spec["source_type"], str(spec["source_id"]), spec["location_key"])
        keep.add(key)
        cfg = {
            "source_managed": True,
            "source_type": spec["source_type"],
            "source_id": spec["source_id"],
            "location_key": spec["location_key"],
        }
        row = by_key.get(key)
        if row is None:
            row = VulnerabilityRepository(
                name=_unique_name(db, spec["name"]),
                feed_type=spec["feed_type"],
                endpoint=spec["endpoint"],
                enabled=spec["enabled"],
                sync_status=spec["sync_status"],
                last_sync_at=spec["last_sync_at"],
                raw_count=spec["raw_count"],
                last_error=spec["last_error"],
                notes=spec["notes"],
                config=cfg,
            )
            db.add(row)
            db.flush()
            by_key[key] = row
            changed = True
            continue
        desired = spec["name"]
        if row.name != desired:
            row.name = _unique_name(db, desired, exclude_id=row.id)
            changed = True
        for field in (
            "feed_type",
            "endpoint",
            "enabled",
            "sync_status",
            "last_sync_at",
            "raw_count",
            "last_error",
            "notes",
        ):
            if getattr(row, field) != spec[field]:
                setattr(row, field, spec[field])
                changed = True
        if _cfg(row) != cfg:
            row.config = cfg
            flag_modified(row, "config")
            changed = True

    for row in managed:
        key = _source_repo_key(row)
        if key is not None and key not in keep:
            db.delete(row)
            changed = True

    if commit and changed:
        db.commit()


def ranked_repositories(rows: list[VulnerabilityRepository]) -> list[VulnerabilityRepository]:
    return sorted(rows, key=lambda row: (_TYPE_RANK.get(row.feed_type, 9), row.id or 0))


def _norm_cve(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    return text if text.startswith("CVE-") else None


def _cves_from_event(extracted: Any, payload: Any) -> set[str]:
    found: set[str] = set()
    for raw in extracted or []:
        cve = _norm_cve(raw)
        if cve:
            found.add(cve)
    blob = payload if isinstance(payload, dict) else {}
    for key in ("cve_id", "cve", "cveId", "cves"):
        value = blob.get(key)
        if isinstance(value, list):
            for item in value:
                cve = _norm_cve(item)
                if cve:
                    found.add(cve)
        else:
            cve = _norm_cve(value)
            if cve:
                found.add(cve)
    for rec in blob.get("records") or []:
        if isinstance(rec, dict):
            cve = _norm_cve(rec.get("cve_id"))
            if cve:
                found.add(cve)
    return found


def _feed_url_key(value: str | None) -> str:
    return str(value or "").strip().rstrip("/")


def repository_cve_counts(db: Session, rows: list[VulnerabilityRepository]) -> dict[int, int]:
    """Unique CVE records in Incoming CVEs per feed row.

    Ingest channels count stored CVEs seen on that source/URL.
    NVD / EPSS count records that actually received that lookup during enrichment.
    """
    from app.models.pipeline import IngestEvent
    from app.models.source import InputSource
    from app.models.vulnerability import Vulnerability

    stored: set[str] = set()
    by_source_name: dict[str, set[str]] = {}
    nvd_ids: set[str] = set()
    epss_ids: set[str] = set()
    for cve_id, source_name, nvd_at, epss_score, enrichment in db.query(
        Vulnerability.cve_id,
        Vulnerability.source_name,
        Vulnerability.nvd_modified_at,
        Vulnerability.epss_score,
        Vulnerability.enrichment,
    ).all():
        cve = _norm_cve(cve_id)
        if not cve:
            continue
        stored.add(cve)
        name = str(source_name or "").strip()
        if name:
            by_source_name.setdefault(name, set()).add(cve)
        blob = enrichment if isinstance(enrichment, dict) else {}
        if nvd_at is not None or blob.get("nvd"):
            nvd_ids.add(cve)
        if epss_score is not None or blob.get("epss"):
            epss_ids.add(cve)

    by_source_id: dict[int, set[str]] = {}
    by_feed_url: dict[str, set[str]] = {}
    for source_id, extracted, payload in db.query(
        IngestEvent.source_id,
        IngestEvent.extracted_cves,
        IngestEvent.payload,
    ).all():
        found = _cves_from_event(extracted, payload) & stored
        if not found:
            continue
        by_source_id.setdefault(int(source_id), set()).update(found)
        blob = payload if isinstance(payload, dict) else {}
        url = _feed_url_key(blob.get("feed_url"))
        if url:
            by_feed_url.setdefault(url, set()).update(found)

    sources = {row.id: row for row in db.query(InputSource).all()}
    out: dict[int, int] = {}
    for row in rows:
        kind = (row.feed_type or "").strip().lower()
        if kind == "nvd":
            out[row.id] = len(nvd_ids)
            continue
        if kind == "epss":
            out[row.id] = len(epss_ids)
            continue
        found: set[str] = set()
        if kind == ATOM_TYPE:
            found |= by_feed_url.get(_feed_url_key(_atom_url(row) or row.endpoint), set())
        cfg = _cfg(row)
        source_id = cfg.get("source_id")
        source = sources.get(int(source_id)) if source_id not in (None, "", 0, "0") else None
        if source is not None:
            found |= by_source_id.get(source.id, set())
            if source.name:
                found |= by_source_name.get(source.name, set())
        out[row.id] = len(found)
    return out
