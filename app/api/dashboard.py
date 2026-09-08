from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.asset import AssetMatch
from app.models.enums import PipelineStatus
from app.models.jira import JiraTicket
from app.models.vulnerability import Vulnerability
from app.schemas.api import DashboardKpis

router = APIRouter()


@router.get("/kpis", response_model=DashboardKpis)
def kpis(db: Session = Depends(get_db)) -> DashboardKpis:
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    ingested_today = (
        db.query(func.count(Vulnerability.id))
        .filter(Vulnerability.created_at >= today)
        .scalar()
        or 0
    )
    pending = (
        db.query(func.count(Vulnerability.id))
        .filter(
            or_(
                Vulnerability.status.in_(
                    (
                        PipelineStatus.INGESTED,
                        PipelineStatus.EXTRACTED,
                        PipelineStatus.ENRICHED,
                        PipelineStatus.AI_FALLBACK,
                    )
                ),
                Vulnerability.pipeline_status.in_(("ingested", "extracting", "enriching")),
            )
        )
        .scalar()
        or 0
    )
    matched = db.query(func.count(func.distinct(AssetMatch.vulnerability_id))).scalar() or 0
    jira_count = db.query(func.count(JiraTicket.id)).scalar() or 0
    completed = (
        db.query(func.count(Vulnerability.id))
        .filter(
            or_(
                Vulnerability.status == PipelineStatus.ACTIONED,
                Vulnerability.pipeline_status == "completed",
            )
        )
        .scalar()
        or 0
    )
    failed = (
        db.query(func.count(Vulnerability.id))
        .filter(
            or_(
                Vulnerability.status == PipelineStatus.FAILED,
                Vulnerability.pipeline_status == "failed",
            )
        )
        .scalar()
        or 0
    )
    critical_open = (
        db.query(func.count(Vulnerability.id))
        .filter(
            Vulnerability.severity == "CRITICAL",
            Vulnerability.status != PipelineStatus.ACTIONED,
            Vulnerability.pipeline_status != "completed",
        )
        .scalar()
        or 0
    )
    return DashboardKpis(
        ingested_today=ingested_today,
        pending_enrichment=pending,
        asset_matched=matched,
        jira_tasks_created=jira_count,
        completed=completed,
        failed=failed,
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
    failed = (
        db.query(Vulnerability)
        .filter(
            or_(
                Vulnerability.status == PipelineStatus.FAILED,
                Vulnerability.pipeline_status == "failed",
            )
        )
        .order_by(Vulnerability.updated_at.desc())
        .limit(8)
        .all()
    )
    for vuln in failed:
        items.append(
            {
                "level": "error",
                "title": f"{vuln.cve_id} pipeline failed",
                "href": f"/vulnerabilities/{vuln.cve_id}",
            }
        )
    pending = (
        db.query(func.count(Vulnerability.id))
        .filter(
            or_(
                Vulnerability.status.in_(
                    (PipelineStatus.INGESTED, PipelineStatus.EXTRACTED, PipelineStatus.ENRICHED)
                ),
                Vulnerability.pipeline_status.in_(("ingested", "extracting", "enriching")),
            )
        )
        .scalar()
        or 0
    )
    if pending:
        items.insert(
            0,
            {
                "level": "warn",
                "title": f"{pending} CVE(s) waiting for enrichment",
                "href": "/",
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
