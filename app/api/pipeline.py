"""Queue views for each pipeline stage dashboard."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.models.asset import AssetMatch
from app.models.detection import DetectionArtifact
from app.models.enums import PipelineStatus
from app.models.jira import JiraTicket
from app.models.pipeline import IngestEvent
from app.models.vulnerability import Vulnerability
from app.services.ingestion import queued_cves_for_event
from app.utils.intel_window import allow_cve

router = APIRouter()

_cleaned_ingest_noise = False

_LEGACY = {
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


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _status(vuln: Vulnerability) -> str:
    status = getattr(vuln, "status", None)
    if isinstance(status, PipelineStatus):
        return status.value
    if status:
        return str(status)
    raw = (getattr(vuln, "pipeline_status", None) or "").strip().lower()
    return _LEGACY.get(raw, (raw or "INGESTED").upper())


def _in_status(vuln: Vulnerability, *wanted: str) -> bool:
    return _status(vuln) in wanted


def _has_intel(vuln: Vulnerability) -> bool:
    """True when NVD or EPSS actually returned data — not merely that the enrich step ran."""
    if getattr(vuln, "cvss_score", None) is not None:
        return True
    if getattr(vuln, "epss_score", None) is not None:
        return True
    blob = getattr(vuln, "enrichment", None) or {}
    return isinstance(blob, dict) and bool(blob.get("nvd") or blob.get("epss"))


def _source_name(vuln: Vulnerability) -> str:
    return getattr(vuln, "source_name", None) or "—"


def _vuln_row(vuln: Vulnerability, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    row = {
        "cve_id": vuln.cve_id,
        "source": _source_name(vuln),
        "status": _status(vuln),
        "vendor": vuln.vendor or "",
        "product": vuln.product or "",
        "severity": vuln.severity or "UNKNOWN",
        "cvss": vuln.cvss_score,
        "epss": vuln.epss_score,
        "attack_vector": vuln.attack_vector or "",
        "ai_extract": bool(getattr(vuln, "ai_extraction_used", False)),
        "ai_enrich": bool(getattr(vuln, "ai_enrichment_used", False)),
        "ai_match": bool(getattr(vuln, "ai_matching_used", False)),
        "updated_at": _iso(getattr(vuln, "updated_at", None)),
        "href": f"/vulnerabilities/{vuln.cve_id}",
    }
    if extra:
        row.update(extra)
    return row


_TICKETING_LABELS = {
    "jira": "Jira",
    "monday": "Monday.com",
    "custom": "CRM",
    "email": "mail relay",
}


def _ticketing_meta() -> dict[str, Any]:
    from app.config import get_settings
    from app.integrations.ticketing import get_ticketing_client

    cfg = get_settings()
    provider = (cfg.ticketing_provider or "jira").lower()
    label = _TICKETING_LABELS.get(provider, "ticketing")
    connected = False
    if cfg.ticketing_enabled:
        connected = bool(getattr(get_ticketing_client(cfg), "configured", False))
    return {"connected": connected, "provider": provider, "provider_label": label}


def _action_status(owner, hunt, ticketing: dict[str, Any]) -> dict[str, str]:
    if not ticketing.get("connected"):
        return {
            "action_state": "not_connected",
            "action_label": "No ticketing system connected",
        }
    name = ticketing.get("provider_label") or "ticketing"
    tickets = list(owner) if isinstance(owner, (list, tuple)) else [owner]
    tickets.append(hunt)
    opened = any(t and not t.dry_run and t.ticket_key for t in tickets)
    if opened:
        return {
            "action_state": "created",
            "action_label": f"New {name} task created",
        }
    return {
        "action_state": "waiting",
        "action_label": f"Waiting to open {name} task",
    }


@router.get("/pipeline/extraction")
def extraction_queue(db: Session = Depends(get_db), include_rows: bool = True) -> dict[str, Any]:
    global _cleaned_ingest_noise
    if not _cleaned_ingest_noise:
        from app.api.settings.common import cleanup_input_sources

        cleanup_input_sources(db)
        db.commit()
        _cleaned_ingest_noise = True
    vulns = db.query(Vulnerability).order_by(Vulnerability.updated_at.desc()).limit(250).all()
    extracted = [v for v in vulns if _in_status(v, "INGESTED", "EXTRACTED") and allow_cve(v.cve_id)]
    failed = [v for v in vulns if _in_status(v, "FAILED") and allow_cve(v.cve_id)]
    ai_used = sum(1 for v in extracted if getattr(v, "ai_extraction_used", False))
    event_rows = []
    duplicates = 0
    event_rows_n = 0
    if include_rows:
        events = (
            db.query(IngestEvent)
            .options(joinedload(IngestEvent.source))
            .order_by(IngestEvent.received_at.desc())
            .limit(500)
            .all()
        )
        seen_cves: set[str] = set()
        for event in events:
            cves = [cve for cve in queued_cves_for_event(event) if allow_cve(cve) and cve not in seen_cves]
            if not cves:
                continue
            seen_cves.update(cves)
            if (event.status or "").lower() in {"duplicate", "skipped"}:
                duplicates += 1
            source = event.source
            payload = event.payload if isinstance(getattr(event, "payload", None), dict) else {}
            event_rows.append(
                {
                    "id": event.id,
                    "source": source.name if source else "—",
                    "filename": payload.get("filename") or "",
                    "cves": cves,
                    "status": event.status or "queued",
                    "error": getattr(event, "error", None),
                    "received_at": _iso(event.received_at),
                    "href": "/sources",
                }
            )
            if len(event_rows) >= 150:
                break
    else:
        duplicates = (
            db.query(func.count(IngestEvent.id))
            .filter(IngestEvent.status.in_(("duplicate", "skipped")))
            .scalar()
            or 0
        )
        event_rows_n = db.query(func.count(IngestEvent.id)).scalar() or 0
    payload = {
        "kpis": {
            "events": len(event_rows) if include_rows else int(event_rows_n),
            "cves": len(extracted),
            "ai_fallback": ai_used,
            "failed": len(failed),
            "duplicates": duplicates,
        },
    }
    if include_rows:
        payload["events"] = event_rows
        payload["rows"] = [_vuln_row(v) for v in extracted + failed[:40]]
    return payload


@router.get("/pipeline/enrichment")
def enrichment_queue(db: Session = Depends(get_db), include_rows: bool = True) -> dict[str, Any]:
    vulns = db.query(Vulnerability).order_by(Vulnerability.updated_at.desc()).limit(250).all()
    in_window = [v for v in vulns if allow_cve(v.cve_id)]
    pending = [v for v in in_window if _in_status(v, "INGESTED", "EXTRACTED")]
    enriched = [v for v in in_window if _has_intel(v)]
    ai_rows = [v for v in in_window if getattr(v, "ai_enrichment_used", False)]
    incomplete = [
        v
        for v in in_window
        if _in_status(v, "EXTRACTED", "ENRICHED")
        and (not _has_intel(v) or not v.vendor or not v.product or v.cvss_score is None)
    ]
    shown: list[Vulnerability] = []
    seen: set[int] = set()
    for vuln in pending + [v for v in in_window if _in_status(v, "ENRICHED")]:
        if vuln.id in seen:
            continue
        seen.add(vuln.id)
        shown.append(vuln)
    rows = []
    if include_rows:
        for vuln in shown:
            missing = [
                name
                for name, ok in (("vendor", vuln.vendor), ("product", vuln.product), ("cvss", vuln.cvss_score))
                if not ok
            ]
            rows.append(
                _vuln_row(
                    vuln,
                    {
                        "missing": missing,
                        "nvd": bool((getattr(vuln, "enrichment", None) or {}).get("nvd")) or vuln.cvss_score is not None,
                        "epss_ok": vuln.epss_score is not None,
                        "intel": _has_intel(vuln),
                    },
                )
            )
    return {
        "kpis": {
            "pending": len(pending),
            "enriched": len(enriched),
            "ai_fallback": len(ai_rows),
            "incomplete": len(incomplete),
        },
        "rows": rows,
    }


@router.get("/pipeline/matching")
def matching_queue(db: Session = Depends(get_db), include_rows: bool = True) -> dict[str, Any]:
    query = db.query(Vulnerability).order_by(Vulnerability.updated_at.desc()).limit(250)
    if include_rows:
        query = query.options(joinedload(Vulnerability.matches).joinedload(AssetMatch.asset))
    vulns = query.all()
    waiting = [v for v in vulns if _in_status(v, "ENRICHED", "AI_FALLBACK")]
    if include_rows:
        matched = [v for v in vulns if _in_status(v, "MATCHED", "ACTIONED") or v.matches]
        unmatched = [v for v in waiting if not v.matches]
    else:
        matched_ids = {
            row[0]
            for row in db.query(AssetMatch.vulnerability_id)
            .filter(AssetMatch.vulnerability_id.in_([v.id for v in vulns] or [0]))
            .distinct()
            .all()
        }
        matched = [v for v in vulns if _in_status(v, "MATCHED", "ACTIONED") or v.id in matched_ids]
        unmatched = [v for v in waiting if v.id not in matched_ids]
    ai_rows = [v for v in vulns if getattr(v, "ai_matching_used", False)]
    rows = []
    if include_rows:
        seen: set[int] = set()
        for vuln in waiting + matched:
            if vuln.id in seen:
                continue
            seen.add(vuln.id)
            assets = []
            for match in vuln.matches or []:
                asset = match.asset
                assets.append(
                    {
                        "name": asset.name if asset else "",
                        "owner": asset.owner_email if asset else "",
                        "team": asset.team if asset else "",
                        "method": match.method,
                        "confidence": match.confidence,
                    }
                )
            first = assets[0] if assets else {}
            rows.append(
                _vuln_row(
                    vuln,
                    {
                        "asset": first.get("name") or "Unmatched",
                        "owner": first.get("owner") or "",
                        "team": first.get("team") or "",
                        "method": first.get("method") or "",
                        "match_count": len(assets),
                    },
                )
            )
    return {
        "kpis": {
            "waiting": len(waiting),
            "matched": len(matched),
            "unmatched": len(unmatched),
            "ai_fallback": len(ai_rows),
        },
        "rows": rows,
    }


@router.get("/pipeline/actions")
def actions_queue(db: Session = Depends(get_db), include_rows: bool = True) -> dict[str, Any]:
    query = db.query(Vulnerability).order_by(Vulnerability.updated_at.desc()).limit(250)
    if include_rows:
        query = query.options(joinedload(Vulnerability.tickets))
    vulns = query.all()
    ready = [v for v in vulns if _in_status(v, "MATCHED")]
    done = [v for v in vulns if _in_status(v, "ACTIONED")]
    vuln_ids = [v.id for v in vulns] or [0]
    tickets = db.query(func.count(JiraTicket.id)).filter(JiraTicket.vulnerability_id.in_(vuln_ids)).scalar() or 0
    hunts = (
        db.query(func.count(JiraTicket.id))
        .filter(
            JiraTicket.vulnerability_id.in_(vuln_ids),
            JiraTicket.ticket_type.in_(("threat_hunt", "hunt")),
        )
        .scalar()
        or 0
    )
    detections = (
        db.query(func.count(func.distinct(DetectionArtifact.vulnerability_id)))
        .filter(DetectionArtifact.vulnerability_id.in_(vuln_ids))
        .scalar()
        or 0
    )
    detection_counts: dict[int, int] = {}
    if include_rows:
        detection_counts = dict(
            db.query(DetectionArtifact.vulnerability_id, func.count(DetectionArtifact.id))
            .filter(DetectionArtifact.vulnerability_id.in_(vuln_ids))
            .group_by(DetectionArtifact.vulnerability_id)
            .all()
        )
    rows = []
    ticketing = _ticketing_meta()
    if include_rows:
        seen: set[int] = set()
        for vuln in ready + done:
            if vuln.id in seen:
                continue
            seen.add(vuln.id)
            owners = [t for t in (vuln.tickets or []) if t.ticket_type == "owner"]
            hunt = next((t for t in (vuln.tickets or []) if t.ticket_type in {"threat_hunt", "hunt"}), None)
            owner = owners[0] if owners else None
            rows.append(
                _vuln_row(
                    vuln,
                    {
                        "owner_ticket": ", ".join((t.assignee or t.ticket_key) for t in owners),
                        "owner_url": owner.url if len(owners) == 1 else "",
                        "hunt_ticket": (hunt.assignee or hunt.ticket_key) if hunt else "",
                        "hunt_url": hunt.url if hunt else "",
                        "dry_run": all(bool(t.dry_run) for t in owners) if owners else False,
                        "detections": int(detection_counts.get(vuln.id, 0)),
                        **_action_status(owners, hunt, ticketing),
                    },
                )
            )
    return {
        "kpis": {
            "ready": len(ready),
            "actioned": len(done),
            "tickets": tickets,
            "hunts": hunts,
            "detections": detections,
        },
        "ticketing": ticketing,
        "rows": rows,
    }
