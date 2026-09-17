"""
Step 1 — ingest.

Listeners (webhooks, Exchange, SMB, ATOM feeds, local files) persist an
``IngestEvent`` via ``ingest_payload``. The orchestrator then calls
``accept_cve`` to insert a Vulnerability row, or to update an existing
row when the same CVE is fetched again from an ATOM feed.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.models.enums import PipelineStatus
from app.models.pipeline import IngestEvent
from app.models.source import InputSource
from app.models.vulnerability import Vulnerability
from app.pipeline.state import apply_status, begin_step, complete_step, write_audit
from app.pipeline.step3_enrich import apply_ingested_fields
from app.services.ingestion import ingest_payload, new_webhook_token

log = logging.getLogger(__name__)

__all__ = ["ingest_payload", "new_webhook_token", "start_event", "accept_cve"]


def start_event(db: Session, event: IngestEvent, source: InputSource | None) -> None:
    event.status = "processing"
    db.commit()
    log.info(
        "Ingest event %s from %s is processing",
        event.id,
        source.name if source else "unknown",
    )


def accept_cve(
    db: Session,
    event: IngestEvent,
    source: InputSource | None,
    cve_id: str,
    *,
    vendor: str | None = None,
    product: str | None = None,
    product_type: str | None = None,
    versions: str | None = None,
    summary: str | None = None,
    ai_used: bool = False,
    refresh: bool = False,
) -> tuple[Vulnerability, str]:
    """Create or refresh a Vulnerability for a CVE.

    Returns ``(vuln, "created" | "updated" | "skipped")``.
    """
    cve_id = cve_id.upper()
    existing = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).one_or_none()
    origin = source.name if source else f"event-{event.id}"
    payload = event.payload if isinstance(getattr(event, "payload", None), dict) else {}
    title = (payload.get("title") or summary or "").strip()
    description = (payload.get("summary") or payload.get("description") or summary or "").strip()
    link = str(payload.get("link") or "").strip()

    if existing is not None:
        if not refresh:
            write_audit(
                db,
                existing,
                PipelineStatus.INGESTED,
                f"{cve_id} already exists — skipping remaining pipeline steps",
                {"event_id": event.id, "duplicate": True},
            )
            db.commit()
            return existing, "skipped"
        if title:
            existing.title = title
        if description:
            existing.description = description
        if vendor:
            existing.vendor = vendor
        if product:
            existing.product = product
        if product_type:
            existing.product_type = product_type
        if versions:
            existing.affected_versions = versions
        apply_ingested_fields(existing, payload)
        if source:
            existing.source_name = source.name
        if link:
            blob = dict(existing.enrichment or {}) if isinstance(existing.enrichment, dict) else {}
            blob["feed_link"] = link
            existing.enrichment = blob
            flag_modified(existing, "enrichment")
        existing.updated_at = datetime.now(timezone.utc)
        write_audit(
            db,
            existing,
            PipelineStatus.INGESTED,
            f"{cve_id} updated from {origin}",
            {"event_id": event.id, "updated": True},
        )
        db.commit()
        return existing, "updated"

    vuln = Vulnerability(
        cve_id=cve_id,
        title=title or cve_id,
        description=description or title or "",
        vendor=vendor,
        product=product,
        product_type=product_type,
        affected_versions=versions,
        source_name=source.name if source else "unknown",
        ai_extraction_used=ai_used,
        enrichment={"feed_link": link} if link else {},
    )
    apply_status(vuln, PipelineStatus.INGESTED)
    apply_ingested_fields(vuln, payload)
    db.add(vuln)
    db.commit()
    db.refresh(vuln)

    begin_step(db, vuln, PipelineStatus.INGESTED, f"Ingest started from {origin}")
    complete_step(
        db,
        vuln,
        PipelineStatus.INGESTED,
        f"Ingested {cve_id} from {origin}",
        {
            "event_id": event.id,
            "source_type": getattr(source, "source_type", None),
        },
    )
    return vuln, "created"
