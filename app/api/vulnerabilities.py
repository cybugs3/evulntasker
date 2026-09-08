from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload, selectinload

from app.db.session import get_db
from app.models.asset import AssetMatch
from app.models.enums import PipelineStatus
from app.models.pipeline import IngestEvent
from app.models.vulnerability import Vulnerability
from app.pipeline.orchestrator import PipelineOrchestrator
from app.schemas.api import AuditLogOut, MatchOut, TicketOut, VulnerabilityOut

router = APIRouter()

_LEGACY_STATUS = {
    "ingested": "INGESTED",
    "extracting": "EXTRACTED",
    "extracted": "EXTRACTED",
    "enriching": "ENRICHED",
    "enriched": "ENRICHED",
    "matching": "MATCHED",
    "matched": "MATCHED",
    "acting": "ACTIONED",
    "completed": "ACTIONED",
    "actioned": "ACTIONED",
    "failed": "FAILED",
    "ai_fallback": "AI_FALLBACK",
}


def _status_value(vuln: Vulnerability) -> str:
    status = getattr(vuln, "status", None)
    if isinstance(status, PipelineStatus):
        return status.value
    if status:
        return str(status)
    raw = (getattr(vuln, "pipeline_status", None) or "").strip().lower()
    return _LEGACY_STATUS.get(raw, (raw or "INGESTED").upper())


def _audit_out(entry) -> dict[str, Any]:
    step = getattr(entry, "pipeline_step", None)
    step_value = step.value if isinstance(step, PipelineStatus) else str(step or "")
    ts = getattr(entry, "timestamp", None)
    return {
        "id": entry.id,
        "cve_id": entry.cve_id,
        "timestamp": ts.isoformat() if ts is not None else None,
        "pipeline_step": step_value,
        "message": entry.message or "",
        "details": entry.details or {},
    }


def _to_out(vuln: Vulnerability) -> VulnerabilityOut:
    tickets = [
        TicketOut(
            ticket_key=t.ticket_key,
            ticket_type=t.ticket_type,
            url=t.url,
            status=t.status,
            dry_run=t.dry_run,
            assignee=getattr(t, "assignee", "") or "",
        )
        for t in vuln.tickets
    ]
    return VulnerabilityOut.model_validate(vuln).model_copy(
        update={"tickets": tickets, "status": _status_value(vuln)}
    )


@router.get("/vulnerabilities", response_model=list[VulnerabilityOut])
def list_vulnerabilities(db: Session = Depends(get_db)) -> list[VulnerabilityOut]:
    rows = (
        db.query(Vulnerability)
        .options(joinedload(Vulnerability.tickets))
        .order_by(Vulnerability.created_at.desc())
        .limit(250)
        .all()
    )
    return [_to_out(v) for v in rows]


@router.get("/cves")
def list_incoming_cves(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = (
        db.query(Vulnerability)
        .order_by(Vulnerability.created_at.desc())
        .limit(500)
        .all()
    )
    return {
        "count": len(rows),
        "rows": [_cve_db_row(v) for v in rows],
    }


def _cve_db_row(vuln: Vulnerability) -> dict[str, Any]:
    title = (vuln.title or "").strip()
    name = title or vuln.cve_id
    return {
        "cve_id": vuln.cve_id,
        "name": name,
        "description": (vuln.description or title or "").strip(),
        "vendor": vuln.vendor or "",
        "product": vuln.product or "",
        "product_type": vuln.product_type or "",
        "version": vuln.affected_versions or "",
        "severity": vuln.severity or "UNKNOWN",
        "cvss_score": vuln.cvss_score,
        "source_name": vuln.source_name or "",
        "created_at": vuln.created_at.isoformat() if vuln.created_at else None,
        "status": _status_value(vuln),
        "href": f"/vulnerabilities/{vuln.cve_id}",
    }


@router.get("/vulnerabilities/{cve_id}")
def get_vulnerability(cve_id: str, db: Session = Depends(get_db)) -> dict:
    vuln = (
        db.query(Vulnerability)
        .options(
            selectinload(Vulnerability.tickets),
            selectinload(Vulnerability.matches).joinedload(AssetMatch.asset),
            selectinload(Vulnerability.detections),
            selectinload(Vulnerability.runs),
            selectinload(Vulnerability.audit_logs),
        )
        .filter(Vulnerability.cve_id == cve_id.upper())
        .one_or_none()
    )
    if not vuln:
        raise HTTPException(404, "CVE not found")

    matches = [
        MatchOut(
            confidence=m.confidence,
            method=m.method,
            asset_name=m.asset.name if m.asset else "",
            owner_email=m.asset.owner_email if m.asset else "",
            team=m.asset.team if m.asset else "",
        )
        for m in vuln.matches
    ]
    detections = [
        {
            "sigma_rule": d.sigma_rule,
            "kql": d.kql,
            "xql": d.xql,
            "aqk": d.aqk,
            "ekql": d.ekql,
        }
        for d in vuln.detections
    ]
    runs = [
        {"id": r.id, "status": r.status, "current_step": r.current_step, "log": r.log}
        for r in vuln.runs
    ]
    audit_logs = [_audit_out(entry) for entry in (vuln.audit_logs or [])]
    audit_logs.sort(key=lambda row: row.get("timestamp") or "")
    data = _to_out(vuln).model_dump()
    data.update(
        {
            "matches": matches,
            "detections": detections,
            "runs": runs,
            "enrichment": vuln.enrichment,
            "audit_logs": audit_logs,
            "status": _status_value(vuln),
        }
    )
    return data


@router.get("/tracker")
def list_tracker(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(Vulnerability).order_by(Vulnerability.created_at.desc()).limit(500).all()
    out = []
    for vuln in rows:
        cwes = getattr(vuln, "cwe_ids", None) or []
        vuln_type = ", ".join(str(x) for x in cwes) if cwes else (getattr(vuln, "product_type", None) or vuln.severity or "—")
        out.append(
            {
                "cve_id": vuln.cve_id,
                "vuln_type": vuln_type,
                "vendor": vuln.vendor,
                "product": vuln.product,
                "version": getattr(vuln, "affected_versions", None) or getattr(vuln, "affected_versions", None),
            }
        )
    return out


@router.get("/tracker/{cve_id}")
def cve_journey(cve_id: str, db: Session = Depends(get_db)) -> dict:
    """Stations a CVE has passed through in EVulnTasker."""
    cve = cve_id.upper().strip()
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve).one_or_none()
    events = db.query(IngestEvent).order_by(IngestEvent.id.desc()).limit(80).all()
    related = []
    for event in events:
        extracted = getattr(event, "extracted_cves", None) or getattr(event, "extracted_cves", None) or []
        payload = getattr(event, "payload", None) or getattr(event, "payload", None) or {}
        if not isinstance(payload, dict):
            payload = {}
        raw = str(getattr(event, "raw_text", "") or getattr(event, "raw_text", "") or "")
        cves = [str(x).upper() for x in list(extracted) + list(payload.get("cves") or [])]
        if cve in cves or cve in raw.upper():
            related.append(event)

    ingest_event = related[0] if related else None
    tickets = list(vuln.tickets) if vuln else []
    enrichment = (vuln.enrichment if vuln else None) or {}
    has_nvd = bool(vuln and (vuln.cvss_score is not None or enrichment.get("nvd") or enrichment.get("epss")))
    enrich_skipped = bool(isinstance(enrichment, dict) and enrichment.get("skipped"))
    skipped = bool(vuln) and any(
        "already exists" in str(entry.get("message") or "")
        for run in (vuln.runs if vuln else [])
        for entry in (run.log or [])
    )
    if vuln and not skipped:
        skipped = False

    def station(key, title, status, detail="", at=None):
        return {"id": key, "title": title, "status": status, "detail": detail, "at": at}

    ingest_at = ingest_event.received_at.isoformat() if ingest_event else (vuln.created_at.isoformat() if vuln else None)
    stations = [
        station(
            "ingest",
            "Input received",
            "done" if (ingest_event or vuln) else "pending",
            (ingest_event and f"Source event #{ingest_event.id}") or ("Record exists" if vuln else "No input yet"),
            ingest_at,
        ),
        station(
            "internal_db",
            "Internal database check",
            "done" if vuln else "pending",
            "CVE already known — pipeline stopped" if skipped else ("CVE stored" if vuln else "Not in SQLite yet"),
            vuln.created_at.isoformat() if vuln else None,
        ),
        station(
            "external_db",
            "External intelligence (NVD / EPSS)",
            "skipped" if skipped or enrich_skipped else ("done" if has_nvd else ("pending" if vuln else "pending")),
            (
                "Skipped; CVE was already processed"
                if skipped
                else (
                    "Enrichment disabled — using ingested fields"
                    if enrich_skipped
                    else ("NVD/EPSS data present" if has_nvd else "Waiting for enrichment")
                )
            ),
            None,
        ),
        station(
            "enrich",
            "Enrichment",
            "skipped" if skipped or enrich_skipped else ("done" if vuln and vuln.pipeline_status in ("matching", "acting", "completed") else ("pending" if vuln else "pending")),
            "Enrichment skipped — using ingested fields" if enrich_skipped else (vuln.pipeline_status if vuln else "Not started"),
            None,
        ),
        station(
            "act",
            "Team task opened",
            "skipped" if skipped else ("done" if tickets else ("pending" if vuln else "pending")),
            ", ".join(t.ticket_key for t in tickets) if tickets else ("No ticket yet" if not skipped else "Skipped"),
            None,
        ),
    ]
    return {
        "cve_id": cve,
        "found": bool(vuln or ingest_event),
        "known": bool(vuln),
        "skipped_as_duplicate": skipped,
        "pipeline_status": vuln.pipeline_status if vuln else None,
        "vendor": vuln.vendor if vuln else None,
        "product": vuln.product if vuln else None,
        "version": vuln.affected_versions if vuln else None,
        "stations": stations,
    }



@router.post("/vulnerabilities/{cve_id}/reprocess")
async def reprocess(cve_id: str, db: Session = Depends(get_db)) -> dict:
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id.upper()).one_or_none()
    if not vuln:
        raise HTTPException(404, "CVE not found")
    orchestrator = PipelineOrchestrator(db)
    from app.models.pipeline import PipelineRun

    run = PipelineRun(vulnerability_id=vuln.id, current_step="enrich", status="running", log=[])
    db.add(run)
    db.commit()
    await orchestrator._enrich_match_act(run, vuln, ai_fallback=True)
    run.status = "completed"
    db.commit()
    return {"status": "ok", "cve_id": vuln.cve_id, "pipeline_status": vuln.pipeline_status}
