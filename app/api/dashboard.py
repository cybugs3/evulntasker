from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.jira import JiraTicket
from app.models.vulnerability import Vulnerability
from app.schemas.api import DashboardKpis
from app.services.workflow import classify_vulnerabilities, count_workflow_states

router = APIRouter()

TREND_RANGES = {
    "24h": (timedelta(hours=24), "hour"),
    "7d": (timedelta(days=7), "day"),
    "30d": (timedelta(days=30), "day"),
    "90d": (timedelta(days=90), "week"),
}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _align(moment: datetime, grain: str) -> datetime:
    moment = _utc(moment)
    if grain == "hour":
        return moment.replace(minute=0, second=0, microsecond=0)
    if grain == "week":
        monday = moment - timedelta(days=moment.weekday())
        return monday.replace(hour=0, minute=0, second=0, microsecond=0)
    return moment.replace(hour=0, minute=0, second=0, microsecond=0)


def _step(grain: str) -> timedelta:
    if grain == "hour":
        return timedelta(hours=1)
    if grain == "week":
        return timedelta(days=7)
    return timedelta(days=1)


def _label(moment: datetime, grain: str) -> str:
    if grain == "hour":
        return moment.strftime("%b %d %H:%M")
    if grain == "week":
        end = moment + timedelta(days=6)
        if moment.month == end.month:
            return f"{moment.strftime('%b %d')}–{end.strftime('%d')}"
        return f"{moment.strftime('%b %d')}–{end.strftime('%b %d')}"
    return moment.strftime("%b %d")


def build_trend_series(
    rows: list[dict],
    *,
    range_key: str = "7d",
    now: datetime | None = None,
) -> dict:
    """Bucket Live Workflow outcomes for CVEs ingested in a time range."""
    now = _utc(now) or datetime.now(timezone.utc)
    span, grain = TREND_RANGES.get(range_key, TREND_RANGES["7d"])
    start = _align(now - span, grain)
    buckets: list[datetime] = []
    cursor = start
    while cursor <= now:
        buckets.append(cursor)
        cursor = cursor + _step(grain)

    ingested_map: dict[datetime, set[int]] = defaultdict(set)
    matched_map: dict[datetime, set[int]] = defaultdict(set)
    unmatched_map: dict[datetime, set[int]] = defaultdict(set)
    waiting_map: dict[datetime, set[int]] = defaultdict(set)

    def place(when: datetime | None, ident: int, into: dict[datetime, set[int]]) -> None:
        stamp = _utc(when)
        if stamp is None or stamp < start:
            return
        key = _align(stamp, grain)
        if key > buckets[-1]:
            key = buckets[-1]
        into[key].add(ident)

    for index, row in enumerate(rows):
        when = row.get("created_at")
        place(when, index, ingested_map)
        stamp = _utc(when)
        if stamp is None or stamp < start:
            continue
        if row.get("matched"):
            place(when, index, matched_map)
        if row.get("unmatched"):
            place(when, index, unmatched_map)
        if row.get("waiting"):
            place(when, index, waiting_map)

    series = []
    for bucket in buckets:
        ingested = len(ingested_map.get(bucket, ()))
        matched = len(matched_map.get(bucket, ()))
        unmatched = len(unmatched_map.get(bucket, ()))
        waiting = len(waiting_map.get(bucket, ()))
        series.append(
            {
                "t": bucket.isoformat(),
                "label": _label(bucket, grain),
                "ingested": ingested,
                "matched": matched,
                "unmatched": unmatched,
                "waiting": waiting,
            }
        )
    ingested_n = sum(row["ingested"] for row in series)
    matched_n = sum(row["matched"] for row in series)
    unmatched_n = sum(row["unmatched"] for row in series)
    waiting_n = sum(row["waiting"] for row in series)
    reached = matched_n + unmatched_n
    return {
        "range": range_key if range_key in TREND_RANGES else "7d",
        "granularity": grain,
        "start": start.isoformat(),
        "end": now.isoformat(),
        "buckets": series,
        "totals": {
            "ingested": ingested_n,
            "matched": matched_n,
            "unmatched": unmatched_n,
            "waiting": waiting_n,
            "match_rate": round((matched_n / reached) * 100) if reached else 0,
        },
    }


@router.get("/kpis", response_model=DashboardKpis)
def kpis(db: Session = Depends(get_db)) -> DashboardKpis:
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    ingested_today = (
        db.query(func.count(Vulnerability.id))
        .filter(Vulnerability.created_at >= today)
        .scalar()
        or 0
    )
    classified = classify_vulnerabilities(db)
    counts = count_workflow_states(classified)
    jira_count = db.query(func.count(JiraTicket.id)).scalar() or 0
    critical_open = sum(
        1
        for item in classified
        if (item["vuln"].severity or "").upper() == "CRITICAL"
        and item["progress"].get("current") is not None
    )
    return DashboardKpis(
        ingested_today=ingested_today,
        pending_enrichment=counts["waiting"],
        asset_matched=counts["matched"],
        jira_tasks_created=jira_count,
        completed=counts["completed"],
        failed=counts["failed"],
        critical_open=critical_open,
    )


@router.get("/overview")
def overview(db: Session = Depends(get_db)) -> dict:
    """KPI cubes for the Main dashboard. Does not load full queue tables."""
    from app.api.inventory import org_inventory
    from app.api.pipeline import actions_queue, enrichment_queue, extraction_queue, matching_queue
    from app.api.sources import sources_kpis

    main = kpis(db).model_dump()
    inventory = org_inventory(db, include_details=False).get("kpis") or {}
    return {
        "main": main,
        "sources": sources_kpis(db),
        "extraction": extraction_queue(db, include_rows=False).get("kpis") or {},
        "enrichment": enrichment_queue(db, include_rows=False).get("kpis") or {},
        "inventory": inventory,
        "matching": matching_queue(db, include_rows=False).get("kpis") or {},
        "actions": actions_queue(db, include_rows=False).get("kpis") or {},
    }


@router.get("/trends")
def ingest_match_trends(
    db: Session = Depends(get_db),
    range: str = "7d",
) -> dict:
    """CVEs ingested in a window, classified with Live Workflow outcomes."""
    range_key = range if range in TREND_RANGES else "7d"
    classified = classify_vulnerabilities(db)
    rows = []
    for item in classified:
        vuln = item["vuln"]
        progress = item["progress"]
        created = _utc(getattr(vuln, "created_at", None))
        if created is None:
            continue
        rows.append(
            {
                "created_at": created,
                "matched": "match" in (progress.get("done") or []),
                "unmatched": bool(progress.get("unmatched")),
                "waiting": bool(progress.get("waiting")),
            }
        )
    return build_trend_series(rows, range_key=range_key)


@router.get("/workflow")
def live_workflow(db: Session = Depends(get_db)) -> dict:
    """Live CVE positions across Ingest → Extraction → Enrichment → Matching → Actions."""
    from app.services.workflow import build_workflow_snapshot

    return build_workflow_snapshot(db)


@router.get("/integrations")
def integration_status(db: Session = Depends(get_db)) -> dict:
    from app.config import get_settings
    from app.models.asset import Asset
    from app.services.intel_sources import lookup_active

    settings = get_settings()
    from app.models.source import InputSource
    from app.services.atom_feed import normalize_feeds

    atom = (
        db.query(InputSource)
        .filter(InputSource.source_type == "web_api")
        .order_by(InputSource.id.asc())
        .first()
    )
    atom_ok = bool(atom and atom.enabled and normalize_feeds(atom.config or {}))
    inventory_count = db.query(func.count(Asset.id)).filter(Asset.active.is_(True)).scalar() or 0
    items = [
        {"name": "ATOM feeds", "ok": atom_ok},
        {"name": "Asset inventory", "ok": inventory_count > 0},
        {"name": "Jira API", "ok": settings.jira_configured},
        {"name": "NVD lookup", "ok": lookup_active("nvd")},
        {"name": "EPSS lookup", "ok": lookup_active("epss")},
        {"name": "CMDB API", "ok": settings.cmdb_connection.configured},
        {"name": "Sonatype API", "ok": settings.sonatype_connection.configured},
        {"name": "ITNM / Discovery", "ok": settings.itnm_connection.configured},
        {"name": "AI module", "ok": settings.ai_configured},
    ]
    return {"integrations": items, "inventory_ready": inventory_count > 0, "inventory_count": inventory_count}


@router.get("/notifications")
def notifications(db: Session = Depends(get_db)) -> dict:
    from app.config import get_settings
    from app.models.source import InputSource

    settings = get_settings()
    items: list[dict] = []
    classified = classify_vulnerabilities(db)
    counts = count_workflow_states(classified)
    failed_items = [item for item in classified if item["progress"].get("failed")][:8]
    for item in failed_items:
        vuln = item["vuln"]
        items.append(
            {
                "level": "error",
                "title": f"{vuln.cve_id} pipeline failed",
                "href": f"/vulnerabilities/{vuln.cve_id}",
            }
        )
    waiting_intel = counts["waiting"]
    inflight = counts["inflight"]
    unmatched = counts["unmatched"]
    if waiting_intel:
        items.insert(
            0,
            {
                "level": "warn",
                "title": f"{waiting_intel} CVE(s) waiting for complete intel",
                "href": "/enrichment",
            },
        )
    elif unmatched:
        items.insert(
            0,
            {
                "level": "warn",
                "title": f"{unmatched} CVE(s) unmatched against Internal systems",
                "href": "/matching",
            },
        )
    elif inflight:
        items.insert(
            0,
            {
                "level": "warn",
                "title": f"{inflight} CVE(s) still in the pipeline",
                "href": "/workflow",
            },
        )
    from app.api.settings.common import MANAGED_SOURCE_TYPES

    for source in db.query(InputSource).filter(InputSource.last_error.isnot(None)).all():
        if source.source_type not in MANAGED_SOURCE_TYPES:
            continue
        if not source.enabled:
            continue
        if source.last_error:
            items.append(
                {
                    "level": "error",
                    "title": f"{source.name}: {source.last_error}",
                    "href": "/sources",
                }
            )
    if not settings.jira_configured:
        items.append({"level": "info", "title": "Jira is not configured", "href": "/settings"})
    from app.models.asset import Asset

    inventory_count = db.query(func.count(Asset.id)).filter(Asset.active.is_(True)).scalar() or 0
    if inventory_count == 0:
        items.insert(
            0,
            {
                "level": "warn",
                "title": "Internal systems database is empty — add rows or import a CSV",
                "href": "/inventory",
            },
        )
    return {"count": len(items), "items": items[:12]}
