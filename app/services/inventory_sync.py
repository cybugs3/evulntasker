"""Load and refresh the local asset catalog that CVE matching uses.

CSV, CMDB, Sonatype, and ITNM/discovery all upsert into `assets`. Matching
never calls those systems per CVE — it queries this table only.
"""

from __future__ import annotations

import csv
import io
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import httpx
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.asset import Asset, AssetMatch
from app.models.inventory_sync import InventorySyncState
from app.utils.textclean import clean_email, sanitize_version

log = logging.getLogger(__name__)

CSV_STORE = Path("./data/inventory/assets.csv")
SAMPLE_CSV = Path(__file__).resolve().parents[1] / "web" / "static" / "samples" / "assets.sample.csv"

SYNC_LOCK = threading.Lock()

HEADER_ALIASES: dict[str, tuple[str, ...]] = {
    "vendor": ("vendor", "manufacturer", "make", "vendor_name", "vendorname"),
    "product": (
        "product",
        "product_name",
        "productname",
        "application",
        "applicationname",
        "software",
        "model",
        "component",
    ),
    "product_type": (
        "product_type",
        "producttype",
        "system_type",
        "systemtype",
        "type",
        "kind",
        "category",
        "class",
        "device_type",
        "devicetype",
    ),
    "version": (
        "version",
        "sw_version",
        "os_version",
        "osversion",
        "firmware",
        "software_version",
        "softwareversion",
    ),
    "name": ("name", "hostname", "asset_name", "assetname", "ci_name", "ciname", "display_name", "sysname"),
    "owner_name": ("owner_name", "owner", "ownername", "asset_owner"),
    "owner_username": ("owner_username", "username", "owner_user"),
    "owner_email": ("owner_email", "email", "owneremail"),
    "team": ("team", "group", "organization", "org", "owner_team"),
    "environment": ("environment", "env"),
    "external_id": ("external_id", "id", "cmdb_id", "asset_id", "device_id", "ci_id"),
}

CSV_EXPORT_HEADERS = (
    "vendor",
    "product",
    "product_type",
    "version",
    "owner_name",
    "owner_email",
    "team",
    "last_update",
)

REMOTE_SOURCES = frozenset({"cmdb", "sonatype", "itnm"})

INTERVAL_PRESETS = (
    (300, "5 minutes"),
    (900, "15 minutes"),
    (1800, "30 minutes"),
    (3600, "1 hour"),
    (21600, "6 hours"),
    (86400, "24 hours"),
)


def inventory_csv_path() -> Path:
    settings = get_settings()
    if settings.is_sqlite:
        db_path = Path(settings.database_url.replace("sqlite:///", ""))
        return db_path.parent / "inventory" / "assets.csv"
    return CSV_STORE


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _norm_key(value: str) -> str:
    return _norm(value).lower().replace("-", "_").replace(" ", "_")


def _pick(row: dict[str, Any], field: str) -> str:
    aliases = HEADER_ALIASES.get(field, (field,))
    lowered = {_norm_key(k): v for k, v in row.items()}
    for alias in aliases:
        if alias in lowered and _norm(lowered[alias]):
            return _norm(lowered[alias])
    return ""


def parse_csv_text(text: str) -> list[dict[str, str]]:
    """Parse an inventory CSV into canonical asset dicts. Skips empty rows."""
    sample = text.lstrip("\ufeff")
    if not sample.strip():
        return []
    reader = csv.DictReader(io.StringIO(sample))
    if not reader.fieldnames:
        raise ValueError("CSV has no header row")
    rows: list[dict[str, str]] = []
    for raw in reader:
        vendor = _pick(raw, "vendor")
        product = _pick(raw, "product")
        if not vendor and not product:
            continue
        name = _pick(raw, "name") or product or vendor
        rows.append(
            {
                "name": name,
                "vendor": vendor,
                "product": product or name,
                "product_type": _pick(raw, "product_type") or "application",
                "version": sanitize_version(_pick(raw, "version")),
                "owner_name": _pick(raw, "owner_name"),
                "owner_username": _pick(raw, "owner_username"),
                "owner_email": clean_email(_pick(raw, "owner_email")),
                "team": _pick(raw, "team"),
                "environment": _pick(raw, "environment") or "production",
                "external_id": _pick(raw, "external_id"),
            }
        )
    return rows


def sample_csv_text() -> str:
    """Header-only CSV template. No demo rows."""
    if SAMPLE_CSV.is_file():
        return SAMPLE_CSV.read_text(encoding="utf-8")
    return "vendor,product,product_type,version,owner_name,owner_email,team\n"


def apply_asset_fields(asset: Asset, payload: dict[str, str], *, source: str | None = None) -> Asset:
    vendor = _norm(payload.get("vendor"))
    product = _norm(payload.get("product"))
    asset.vendor = vendor
    asset.product = product or _norm(payload.get("name"))
    asset.system_type = _norm(payload.get("product_type") or payload.get("system_type"))
    asset.version = sanitize_version(payload.get("version"))
    asset.owner_name = _norm(payload.get("owner_name"))
    asset.owner_username = _norm(payload.get("owner_username"))
    asset.owner_email = clean_email(payload.get("owner_email"))
    asset.team = _norm(payload.get("team"))
    if payload.get("environment"):
        asset.environment = _norm(payload["environment"])
    asset.name = _norm(payload.get("name")) or asset.product or asset.vendor or "unnamed"
    if source:
        asset.source = source
    asset.active = True
    return asset


def save_manual_asset(db: Session, payload: dict[str, str], asset: Asset | None = None) -> tuple[Asset, bool]:
    vendor = _norm(payload.get("vendor"))
    product = _norm(payload.get("product"))
    if not vendor or not product:
        raise ValueError("Vendor and product are required.")
    now = datetime.now(timezone.utc)
    created = asset is None
    row = asset or Asset(source="manual")
    apply_asset_fields(row, payload, source="manual" if created else (row.source or "manual"))
    if created or row.source not in {"csv", "manual"}:
        row.source = "manual"
    row.last_synced_at = now
    if created:
        db.add(row)
    db.commit()
    db.refresh(row)
    return row, created


def delete_assets(db: Session, asset_ids: list[int]) -> int:
    ids = sorted({int(item) for item in asset_ids if item is not None})
    if not ids:
        return 0
    existing = [row[0] for row in db.query(Asset.id).filter(Asset.id.in_(ids)).all()]
    if not existing:
        return 0
    db.query(AssetMatch).filter(AssetMatch.asset_id.in_(existing)).delete(synchronize_session=False)
    deleted = db.query(Asset).filter(Asset.id.in_(existing)).delete(synchronize_session=False)
    db.commit()
    return int(deleted or 0)


def delete_asset(db: Session, asset_id: int) -> bool:
    return delete_assets(db, [asset_id]) > 0


def is_placeholder_asset(asset: Asset) -> bool:
    name = (asset.name or "").strip().lower()
    email = (asset.owner_email or "").strip().lower()
    if name.startswith("ai-mapped"):
        return True
    if email.endswith("@example.com"):
        return True
    return False


def purge_placeholder_assets(db: Session) -> int:
    """Remove demo catalog rows and old AI-invented assets. Does not commit."""
    removed = 0
    for asset in db.query(Asset).all():
        if not is_placeholder_asset(asset):
            continue
        db.query(AssetMatch).filter(AssetMatch.asset_id == asset.id).delete(synchronize_session=False)
        db.delete(asset)
        removed += 1
    return removed


def scrub_catalog_fields(db: Session) -> int:
    """Fix RTL emails and float-noise versions already stored in Internal systems."""
    changed = 0
    for asset in db.query(Asset).all():
        email = clean_email(asset.owner_email)
        version = sanitize_version(asset.version)
        if email != (asset.owner_email or "") or version != (asset.version or ""):
            asset.owner_email = email
            asset.version = version
            changed += 1
    return changed


def get_or_create_state(db: Session, source: str) -> InventorySyncState:
    row = db.query(InventorySyncState).filter(InventorySyncState.source == source).one_or_none()
    if row:
        return row
    row = InventorySyncState(source=source)
    db.add(row)
    db.flush()
    return row


def _find_existing(db: Session, source: str, payload: dict[str, str]) -> Asset | None:
    external_id = payload.get("external_id") or ""
    if external_id:
        found = (
            db.query(Asset)
            .filter(Asset.source == source, Asset.external_id == external_id)
            .one_or_none()
        )
        if found:
            return found
    vendor = (payload.get("vendor") or "").lower()
    product = (payload.get("product") or "").lower()
    version = (payload.get("version") or "").lower()
    name = (payload.get("name") or "").lower()
    q = db.query(Asset).filter(
        Asset.source == source,
        func.lower(Asset.vendor) == vendor,
        func.lower(Asset.product) == product,
        func.lower(Asset.version) == version,
    )
    if name:
        q = q.filter(func.lower(Asset.name) == name)
    return q.one_or_none()


def upsert_asset(
    db: Session,
    source: str,
    payload: dict[str, str],
    now: datetime | None = None,
    *,
    new_only: bool = False,
) -> tuple[Asset, bool]:
    now = now or datetime.now(timezone.utc)
    existing = _find_existing(db, source, payload)
    if existing is not None and new_only:
        return existing, False
    system_type = payload.get("product_type") or payload.get("system_type") or "application"
    created = existing is None
    asset = existing or Asset(source=source)
    asset.name = payload.get("name") or payload.get("product") or payload.get("vendor") or "unnamed"
    asset.vendor = payload.get("vendor") or ""
    asset.product = payload.get("product") or asset.name
    asset.version = payload.get("version") or ""
    asset.system_type = system_type
    if payload.get("owner_name"):
        asset.owner_name = payload["owner_name"]
    if payload.get("owner_username"):
        asset.owner_username = payload["owner_username"]
    if payload.get("owner_email"):
        asset.owner_email = payload["owner_email"]
    if payload.get("team"):
        asset.team = payload["team"]
    if payload.get("environment"):
        asset.environment = payload["environment"]
    if payload.get("external_id"):
        asset.external_id = payload["external_id"]
        if source == "cmdb":
            asset.cmdb_id = payload["external_id"]
        elif source == "sonatype":
            asset.sonatype_id = payload["external_id"]
    asset.active = True
    asset.last_synced_at = now
    asset.source = source
    if created:
        db.add(asset)
    return asset, created


def upsert_rows(db: Session, source: str, rows: Iterable[dict[str, str]]) -> dict[str, int]:
    now = datetime.now(timezone.utc)
    created = 0
    updated = 0
    new_only = source in REMOTE_SOURCES
    for payload in rows:
        _, is_new = upsert_asset(db, source, payload, now=now, new_only=new_only)
        if is_new:
            created += 1
        elif not new_only:
            updated += 1
    total = created + updated
    state = get_or_create_state(db, source)
    state.last_sync_at = now
    state.last_error = None
    state.last_count = total
    state.last_created = created
    state.last_updated = updated
    return {"source": source, "count": total, "created": created, "updated": updated}


def import_csv_text(db: Session, text: str, *, persist_file: bool = True) -> dict[str, int]:
    rows = parse_csv_text(text)
    if not rows:
        raise ValueError("No asset rows found. Need at least vendor or product.")
    if persist_file:
        path = inventory_csv_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    result = upsert_rows(db, "csv", rows)
    db.commit()
    return result


def _unwrap_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("items", "assets", "applications", "devices", "results", "data", "nodes"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return [data]


def fetch_remote_list(conn, extra_path: str) -> list[dict[str, Any]]:
    if not conn.configured:
        return []
    url = conn.base_url.rstrip("/") + "/" + extra_path.lstrip("/")
    headers = {"User-Agent": "EVulnTasker/1.0", "Accept": "application/json", **conn.auth_headers()}
    with httpx.Client(timeout=30.0, verify=conn.httpx_verify()) as client:
        response = client.get(url, headers=headers, auth=conn.auth_basic())
        response.raise_for_status()
        return _unwrap_list(response.json())


def normalize_remote(raw: dict[str, Any], *, default_type: str) -> dict[str, str]:
    vendor = _pick(raw, "vendor")
    product = _pick(raw, "product")
    name = _pick(raw, "name") or product or vendor or "unnamed"
    external_id = _pick(raw, "external_id")
    if not external_id and raw.get("publicId"):
        external_id = str(raw.get("publicId"))
    if not vendor and raw.get("organizationName"):
        vendor = str(raw.get("organizationName"))
    return {
        "name": name,
        "vendor": vendor,
        "product": product or name,
        "product_type": _pick(raw, "product_type") or default_type,
        "version": _pick(raw, "version"),
        "owner_name": _pick(raw, "owner_name"),
        "owner_username": _pick(raw, "owner_username"),
        "owner_email": _pick(raw, "owner_email"),
        "team": _pick(raw, "team"),
        "environment": _pick(raw, "environment") or "production",
        "external_id": external_id,
    }


def _record_error(db: Session, source: str, exc: Exception) -> dict[str, Any]:
    log.exception("Inventory sync failed for %s", source)
    state = get_or_create_state(db, source)
    state.last_error = str(exc)
    db.commit()
    return {"source": source, "ok": False, "error": str(exc), "count": 0, "created": 0, "updated": 0}


def sync_csv_file(db: Session) -> dict[str, Any] | None:
    path = inventory_csv_path()
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    try:
        result = import_csv_text(db, text, persist_file=False)
        return {"ok": True, **result}
    except Exception as exc:
        return _record_error(db, "csv", exc)


def sync_cmdb(db: Session) -> dict[str, Any] | None:
    settings = get_settings()
    conn = settings.cmdb_connection
    if not conn.configured:
        return None
    try:
        remotes = fetch_remote_list(conn, "/assets")
        rows = [normalize_remote(item, default_type="application") for item in remotes]
        result = upsert_rows(db, "cmdb", rows)
        db.commit()
        return {"ok": True, **result}
    except Exception as exc:
        return _record_error(db, "cmdb", exc)


def sync_sonatype(db: Session) -> dict[str, Any] | None:
    settings = get_settings()
    conn = settings.sonatype_connection
    if not conn.configured:
        return None
    try:
        from app.integrations.sonatype import SonatypeClient

        rows = SonatypeClient(conn).harvest_catalog()
        result = upsert_rows(db, "sonatype", rows)
        db.commit()
        return {"ok": True, **result}
    except Exception as exc:
        return _record_error(db, "sonatype", exc)


def start_sonatype_sync() -> None:
    """Learn IQ applications + libraries after Settings save. Does not wait."""

    def _run() -> None:
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            sync_sonatype(db)
        except Exception:
            log.exception("Sonatype catalog sync after save failed")
        finally:
            db.close()

    threading.Thread(target=_run, name="sonatype-catalog-sync", daemon=True).start()


def sync_itnm(db: Session) -> dict[str, Any] | None:
    settings = get_settings()
    conn = settings.itnm_connection
    if not conn.configured:
        return None
    list_path = settings.itnm_list_path or "/devices"
    try:
        remotes = fetch_remote_list(conn, list_path)
        rows = [normalize_remote(item, default_type="network") for item in remotes]
        result = upsert_rows(db, "itnm", rows)
        db.commit()
        return {"ok": True, **result}
    except Exception as exc:
        return _record_error(db, "itnm", exc)


def sync_all(db: Session, *, sources: list[str] | None = None) -> dict[str, Any]:
    """Refresh selected sources into the local catalog. Safe to call from the scheduler."""
    wanted = set(sources) if sources else {"csv", "cmdb", "sonatype", "itnm"}
    runners = {
        "csv": sync_csv_file,
        "cmdb": sync_cmdb,
        "sonatype": sync_sonatype,
        "itnm": sync_itnm,
    }
    results: list[dict[str, Any]] = []
    if not SYNC_LOCK.acquire(blocking=False):
        return {"ok": False, "error": "A sync is already running", "results": []}
    try:
        for name in ("csv", "cmdb", "sonatype", "itnm"):
            if name not in wanted:
                continue
            outcome = runners[name](db)
            if outcome is not None:
                results.append(outcome)
        now = datetime.now(timezone.utc)
        state = get_or_create_state(db, "all")
        state.last_sync_at = now
        errors = [r.get("error") for r in results if not r.get("ok", True) and r.get("error")]
        state.last_error = "; ".join(errors) if errors else None
        state.last_count = sum(int(r.get("count") or 0) for r in results)
        state.last_created = sum(int(r.get("created") or 0) for r in results)
        state.last_updated = sum(int(r.get("updated") or 0) for r in results)
        db.commit()
        return {
            "ok": not errors,
            "results": results,
            "count": state.last_count,
            "created": state.last_created,
            "updated": state.last_updated,
            "last_sync_at": now.isoformat(),
        }
    finally:
        SYNC_LOCK.release()


def maybe_sync_inventory() -> dict[str, Any] | None:
    """Scheduler entry: sync when the configured interval has elapsed."""
    settings = get_settings()
    if not settings.inventory_sync_enabled:
        return None
    interval = max(60, int(settings.inventory_sync_seconds or 86400))
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        state = get_or_create_state(db, "all")
        now = datetime.now(timezone.utc)
        last = state.last_sync_at
        if last is not None:
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            if (now - last).total_seconds() < interval:
                return None
        log.info("Scheduled inventory sync (every %ss)", interval)
        return sync_all(db)
    except Exception:
        log.exception("Scheduled inventory sync failed")
        return None
    finally:
        db.close()


def inventory_status(db: Session) -> dict[str, Any]:
    settings = get_settings()
    total = db.query(func.count(Asset.id)).filter(Asset.active.is_(True)).scalar() or 0
    by_source: dict[str, int] = {}
    for source, count in (
        db.query(Asset.source, func.count(Asset.id))
        .filter(Asset.active.is_(True))
        .group_by(Asset.source)
        .all()
    ):
        by_source[source or "local"] = count
    states = {row.source: row for row in db.query(InventorySyncState).all()}

    def _state(name: str) -> dict[str, Any]:
        row = states.get(name)
        return {
            "last_sync_at": row.last_sync_at.isoformat() if row and row.last_sync_at else None,
            "last_error": row.last_error if row else None,
            "last_count": row.last_count if row else 0,
            "last_created": row.last_created if row else 0,
            "last_updated": row.last_updated if row else 0,
        }

    csv_path = inventory_csv_path()
    return {
        "ready": total > 0,
        "asset_count": total,
        "by_source": by_source,
        "csv_loaded": csv_path.is_file(),
        "sync_enabled": bool(settings.inventory_sync_enabled),
        "sync_seconds": max(60, int(settings.inventory_sync_seconds or 86400)),
        "interval_presets": [{"seconds": s, "label": label} for s, label in INTERVAL_PRESETS],
        "sources": {
            "csv": {"enabled": True, "configured": csv_path.is_file(), **_state("csv")},
            "cmdb": {
                "enabled": settings.cmdb_enabled,
                "configured": settings.cmdb_connection.configured,
                **_state("cmdb"),
            },
            "sonatype": {
                "enabled": settings.sonatype_enabled,
                "configured": settings.sonatype_connection.configured,
                **_state("sonatype"),
            },
            "itnm": {
                "enabled": settings.itnm_enabled,
                "configured": settings.itnm_connection.configured,
                **_state("itnm"),
            },
        },
        "all": _state("all"),
    }


def catalog_rows(db: Session, limit: int = 250) -> list[dict[str, Any]]:
    assets = (
        db.query(Asset)
        .filter(Asset.active.is_(True))
        .order_by(Asset.vendor, Asset.product, Asset.version)
        .limit(limit)
        .all()
    )
    return [
        {
            "id": a.id,
            "name": a.name,
            "vendor": a.vendor,
            "product": a.product,
            "product_type": a.system_type,
            "version": a.version,
            "source": a.source or "local",
            "owner_name": a.owner_name,
            "owner_email": a.owner_email,
            "team": a.team,
            "environment": a.environment,
            "last_synced_at": a.last_synced_at.isoformat() if a.last_synced_at else None,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "last_update": (a.last_synced_at or a.created_at).isoformat()
            if (a.last_synced_at or a.created_at)
            else None,
        }
        for a in assets
    ]


def _csv_cell(value: Any) -> str:
    text = str(value or "")
    if text[:1] in {"=", "+", "-", "@"}:
        return f"'{text}"
    return text


def export_catalog_csv(db: Session) -> str:
    """Dump the Systems database as CSV using the same headers as Import CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_EXPORT_HEADERS)
    for row in catalog_rows(db, limit=100_000):
        writer.writerow(
            [
                _csv_cell(row.get("vendor")),
                _csv_cell(row.get("product")),
                _csv_cell(row.get("product_type")),
                _csv_cell(row.get("version")),
                _csv_cell(row.get("owner_name")),
                _csv_cell(row.get("owner_email")),
                _csv_cell(row.get("team")),
                _csv_cell(row.get("last_update")),
            ]
        )
    return buf.getvalue()
