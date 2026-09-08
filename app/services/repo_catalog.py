"""Catalog rows on Vulnerability Repositories: intel lookups + operator ATOM feeds."""

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
        return True
    return bool(row.enabled)


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
                enabled=True,
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
