"""Queue views for each pipeline stage dashboard."""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.models.detection import DetectionArtifact
from app.models.enums import PipelineStatus
from app.models.jira import JiraTicket
from app.models.pipeline import IngestEvent
from app.models.vulnerability import Vulnerability
from app.services.ingestion import queued_cves_for_event
from app.services.workflow import (
    _has_intel,
    classify_vulnerabilities,
    count_workflow_states,
    reached_actions,
    reached_enrichment,
    reached_matching,
    workflow_flags,
)

_ROW_LIMIT = 250

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


def _source_name(vuln: Vulnerability) -> str:
    return getattr(vuln, "source_name", None) or "—"


def _vuln_row(
    vuln: Vulnerability,
    extra: dict[str, Any] | None = None,
    progress: dict[str, Any] | None = None,
) -> dict[str, Any]:
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
    if progress:
        row.update(workflow_flags(progress))
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
    from app.integrations.ticketing import get_ticketing_clients

    cfg = get_settings()
    clients = get_ticketing_clients(cfg)
    connected_names = [name for name, client in clients if getattr(client, "configured", False)]
    if connected_names:
        label = " + ".join(_TICKETING_LABELS.get(name, name) for name in connected_names)
    elif clients:
        label = " + ".join(_TICKETING_LABELS.get(name, name) for name, _client in clients)
    else:
        label = "ticketing"
    return {
        "connected": bool(connected_names),
        "provider": connected_names[0] if connected_names else (clients[0][0] if clients else ""),
        "providers": [name for name, _client in clients],
        "provider_label": label,
    }


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


def _ticket_obj(payload: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(
        assignee=payload.get("assignee") or "",
        ticket_key=payload.get("key") or "",
        url=payload.get("url") or "",
        dry_run=bool(payload.get("dry_run")),
        ticket_type=payload.get("type") or "",
    )


@router.get("/pipeline/extraction")
def extraction_queue(db: Session = Depends(get_db), include_rows: bool = True) -> dict[str, Any]:
    global _cleaned_ingest_noise
    if not _cleaned_ingest_noise:
        from app.api.settings.common import cleanup_input_sources

        cleanup_input_sources(db)
        db.commit()
        _cleaned_ingest_noise = True
    classified = classify_vulnerabilities(db)
    counts = count_workflow_states(classified)
    event_rows = []
    duplicates = 0
    event_rows_n = 0
    if include_rows:
        events = (
            db.query(IngestEvent)
            .options(joinedload(IngestEvent.source))
            .order_by(IngestEvent.received_at.desc(), IngestEvent.id.desc())
            .limit(500)
            .all()
        )
        seen_files: set[tuple[int, str]] = set()
        for event in events:
            payload = event.payload if isinstance(getattr(event, "payload", None), dict) else {}
            filename = str(payload.get("filename") or "").strip()
            cves = queued_cves_for_event(event)
            if not cves and not filename:
                continue
            if filename:
                file_key = (event.source_id, filename.lower())
                if file_key in seen_files:
                    continue
                seen_files.add(file_key)
            if (event.status or "").lower() in {"duplicate", "skipped"}:
                duplicates += 1
            source = event.source
            event_rows.append(
                {
                    "id": event.id,
                    "source": source.name if source else "—",
                    "filename": filename,
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
            "cves": counts["cves"],
            "ai_fallback": counts["ai_extract"],
            "failed": sum(
                1
                for item in classified
                if item["progress"].get("failed")
                and item["progress"].get("current") in {"ingest", "extract"}
            ),
            "duplicates": duplicates,
        },
    }
    if include_rows:
        payload["events"] = event_rows
        payload["rows"] = [
            _vuln_row(item["vuln"], progress=item["progress"]) for item in classified[:_ROW_LIMIT]
        ]
    return payload


@router.get("/pipeline/enrichment")
def enrichment_queue(db: Session = Depends(get_db), include_rows: bool = True) -> dict[str, Any]:
    classified = classify_vulnerabilities(db)
    counts = count_workflow_states(classified)
    rows = []
    if include_rows:
        shown = [item for item in classified if reached_enrichment(item["progress"])][:_ROW_LIMIT]
        for item in shown:
            vuln = item["vuln"]
            progress = item["progress"]
            blob = getattr(vuln, "enrichment", None) or {}
            skipped = isinstance(blob, dict) and bool(blob.get("skipped"))
            waiting = bool(progress.get("waiting"))
            missing = [
                name
                for name, ok in (("vendor", vuln.vendor), ("product", vuln.product), ("cvss", vuln.cvss_score))
                if not ok
            ]
            if waiting and isinstance(blob, dict) and blob.get("missing"):
                missing = list(blob.get("missing") or missing)
            rows.append(
                _vuln_row(
                    vuln,
                    {
                        "missing": missing,
                        "nvd": bool((blob if isinstance(blob, dict) else {}).get("nvd"))
                        or vuln.cvss_score is not None,
                        "epss_ok": vuln.epss_score is not None,
                        "intel": _has_intel(vuln),
                        "skipped": skipped,
                        "waiting": waiting,
                        "wait_reason": (blob.get("wait_reason") if isinstance(blob, dict) else None),
                        "wait_kind": (blob.get("wait_kind") if isinstance(blob, dict) else None),
                        "retry_at": (blob.get("retry_at") if isinstance(blob, dict) else None),
                    },
                    progress=progress,
                )
            )
    return {
        "kpis": {
            "pending": counts["waiting"],
            "enriched": counts["enriched"],
            "ai_fallback": counts["ai_enrich"],
            "incomplete": counts["incomplete"],
            "waiting": counts["waiting"],
        },
        "rows": rows,
    }


@router.get("/pipeline/matching")
def matching_queue(db: Session = Depends(get_db), include_rows: bool = True) -> dict[str, Any]:
    classified = classify_vulnerabilities(db)
    counts = count_workflow_states(classified)
    rows = []
    if include_rows:
        shown = [item for item in classified if reached_matching(item["progress"])][:_ROW_LIMIT]
        for item in shown:
            vuln = item["vuln"]
            progress = item["progress"]
            assets = item["matches"]
            first = assets[0] if assets else {}
            rows.append(
                _vuln_row(
                    vuln,
                    {
                        "asset": first.get("name") or "Unmatched",
                        "owner": first.get("owner_email") or "",
                        "team": first.get("team") or "",
                        "method": first.get("method") or "",
                        "match_count": len(assets),
                    },
                    progress=progress,
                )
            )
    return {
        "kpis": {
            "waiting": counts["matching_live"],
            "matched": counts["matched"],
            "unmatched": counts["unmatched"],
            "ai_fallback": counts["ai_match"],
        },
        "rows": rows,
    }


@router.get("/pipeline/actions")
def actions_queue(db: Session = Depends(get_db), include_rows: bool = True) -> dict[str, Any]:
    classified = classify_vulnerabilities(db)
    counts = count_workflow_states(classified)
    action_items = [item for item in classified if reached_actions(item["progress"])]
    vuln_ids = [item["vuln"].id for item in action_items] or [0]
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
        for item in action_items[:_ROW_LIMIT]:
            vuln = item["vuln"]
            owners = [_ticket_obj(t) for t in item["tickets"] if t.get("type") == "owner"]
            hunt_row = next((t for t in item["tickets"] if t.get("type") in {"threat_hunt", "hunt"}), None)
            hunt = _ticket_obj(hunt_row) if hunt_row else None
            owner = owners[0] if owners else None
            rows.append(
                _vuln_row(
                    vuln,
                    {
                        "owner_ticket": ", ".join((t.assignee or t.ticket_key) for t in owners),
                        "owner_url": owner.url if owner and len(owners) == 1 else "",
                        "hunt_ticket": (hunt.assignee or hunt.ticket_key) if hunt else "",
                        "hunt_url": hunt.url if hunt else "",
                        "dry_run": all(bool(t.dry_run) for t in owners) if owners else False,
                        "detections": int(detection_counts.get(vuln.id, 0)),
                        **_action_status(owners, hunt, ticketing),
                    },
                    progress=item["progress"],
                )
            )
    return {
        "kpis": {
            "ready": counts["acting_live"],
            "actioned": counts["actioned"],
            "tickets": counts["tickets"],
            "hunts": hunts,
            "detections": detections,
        },
        "ticketing": ticketing,
        "rows": rows,
    }
