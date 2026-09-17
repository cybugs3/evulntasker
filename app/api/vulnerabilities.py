from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, joinedload, selectinload

from app.db.session import get_db
from app.models.asset import AssetMatch
from app.models.enums import PipelineStatus
from app.models.vulnerability import Vulnerability
from app.schemas.api import AuditLogOut, MatchOut, TicketOut, VulnerabilityOut
from app.services.ingestion import InlineIngestError, queue_cve_rerun
from app.services.wipe import delete_incoming_cves
from app.services.workflow import (
    canonical_pipeline_status,
    classify_vulnerabilities,
    progress_for_vuln,
    station_journey,
    workflow_flags,
)

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
        update={
            "tickets": tickets,
            "status": _status_value(vuln),
            "pipeline_status": canonical_pipeline_status(vuln),
        }
    )


@router.get("/vulnerabilities", response_model=list[VulnerabilityOut])
def list_vulnerabilities(db: Session = Depends(get_db)) -> list[VulnerabilityOut]:
    rows = (
        db.query(Vulnerability)
        .options(joinedload(Vulnerability.tickets))
        .order_by(Vulnerability.updated_at.desc())
        .limit(250)
        .all()
    )
    classified = classify_vulnerabilities(db, rows)
    out = []
    for item in classified:
        flags = workflow_flags(item["progress"])
        out.append(
            _to_out(item["vuln"]).model_copy(
                update={
                    "station": flags["station"],
                    "station_label": flags["station_label"],
                    "run": flags["run"],
                    "run_label": flags["run_label"],
                    "filter_key": flags["filter_key"],
                    "unmatched": flags["unmatched"],
                    "waiting": flags["waiting"],
                }
            )
        )
    return out


class CveDeleteIn(BaseModel):
    cve_ids: list[str] = Field(min_length=1, max_length=500)


@router.post("/cves/delete")
def delete_selected_incoming_cves(body: CveDeleteIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        return delete_incoming_cves(db, body.cve_ids)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/cves")
def list_incoming_cves(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = (
        db.query(Vulnerability)
        .order_by(Vulnerability.created_at.desc())
        .limit(500)
        .all()
    )
    classified = classify_vulnerabilities(db, rows)
    return {
        "count": len(classified),
        "rows": [_cve_db_row(item["vuln"], item["progress"]) for item in classified],
    }


def _cve_db_row(vuln: Vulnerability, progress: dict[str, Any] | None = None) -> dict[str, Any]:
    flags = workflow_flags(progress or {})
    title = (vuln.title or "").strip()
    name = title or vuln.cve_id
    matched = bool(flags.get("matched"))
    unmatched = bool(flags.get("unmatched"))
    if matched:
        match_label = "TRUE"
    elif unmatched:
        match_label = "UNMATCHED"
    else:
        match_label = "—"
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
        "matched": matched,
        "unmatched": unmatched,
        "match_label": match_label,
        "station": flags.get("station"),
        "station_label": flags.get("station_label"),
        "run_label": flags.get("run_label"),
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
    progress = progress_for_vuln(
        vuln, has_match=bool(vuln.matches), has_ticket=bool(vuln.tickets)
    )
    flags = workflow_flags(progress)
    data = _to_out(vuln).model_dump()
    data.update(
        {
            "matches": matches,
            "detections": detections,
            "runs": runs,
            "enrichment": vuln.enrichment,
            "audit_logs": audit_logs,
            "status": _status_value(vuln),
            "stations": station_journey(progress),
            **flags,
        }
    )
    return data


@router.get("/tracker/{cve_id}")
def cve_journey(cve_id: str, db: Session = Depends(get_db)) -> dict:
    """Live Workflow stations a CVE has passed through."""
    cve = cve_id.upper().strip()
    vuln = (
        db.query(Vulnerability)
        .options(
            selectinload(Vulnerability.tickets),
            selectinload(Vulnerability.matches),
        )
        .filter(Vulnerability.cve_id == cve)
        .one_or_none()
    )
    if vuln is None:
        return {
            "cve_id": cve,
            "found": False,
            "known": False,
            "skipped_as_duplicate": False,
            "pipeline_status": None,
            "vendor": None,
            "product": None,
            "version": None,
            "stations": station_journey({}),
            **workflow_flags({}),
        }
    progress = progress_for_vuln(
        vuln, has_match=bool(vuln.matches), has_ticket=bool(vuln.tickets)
    )
    flags = workflow_flags(progress)
    return {
        "cve_id": cve,
        "found": True,
        "known": True,
        "skipped_as_duplicate": False,
        "pipeline_status": canonical_pipeline_status(vuln),
        "vendor": vuln.vendor,
        "product": vuln.product,
        "version": vuln.affected_versions,
        "stations": station_journey(progress),
        **flags,
    }



@router.post("/vulnerabilities/{cve_id}/reprocess")
def reprocess(cve_id: str, db: Session = Depends(get_db)) -> dict:
    try:
        event = queue_cve_rerun(db, cve_id)
    except InlineIngestError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc
    cves = list(event.extracted_cves or [])
    label = str(cves[0] if cves else cve_id).upper()
    return {"status": "queued", "cve_id": label, "event_id": event.id}
