"""Shared pipeline state: status transitions and AuditLog writes.

Database access uses the application's SQLAlchemy ``Session`` (the same
session the FastAPI/worker process already holds). Integration I/O is
async; commits stay on this session.
"""

from __future__ import annotations

import logging
import traceback
from typing import Any

from sqlalchemy.orm import Session

from app.models.audit import AuditLog
from app.models.enums import PipelineStatus
from app.models.vulnerability import Vulnerability
from app.utils.jsonutil import jsonable

log = logging.getLogger(__name__)

# Compatibility string column. Live Workflow is the operator-facing classifier;
# these values exist so old filters and waiting-intel retries keep working.
WAITING_ENRICHMENT = "waiting_enrichment"
_DASHBOARD_STATUS = {
    PipelineStatus.INGESTED: "ingested",
    PipelineStatus.EXTRACTED: "extracting",
    PipelineStatus.ENRICHED: "enriching",
    PipelineStatus.MATCHED: "matching",
    PipelineStatus.ACTIONED: "completed",
    PipelineStatus.AI_FALLBACK: "enriching",
    PipelineStatus.FAILED: "failed",
}


def dashboard_for(status: PipelineStatus, *, waiting: bool = False) -> str:
    if waiting:
        return WAITING_ENRICHMENT
    return _DASHBOARD_STATUS.get(status, "ingested")


def apply_status(
    vuln: Vulnerability,
    status: PipelineStatus,
    *,
    waiting: bool = False,
) -> None:
    """Write ``status`` and ``pipeline_status`` together so they cannot drift."""
    vuln.status = status
    if hasattr(vuln, "pipeline_status"):
        vuln.pipeline_status = dashboard_for(status, waiting=waiting)


def pick(obj: Any, *names: str, default: Any = None) -> Any:
    """Return the first present, non-empty attribute or mapping key."""
    for name in names:
        if obj is None:
            break
        if isinstance(obj, dict):
            if name in obj and obj[name] not in (None, ""):
                return obj[name]
            continue
        if hasattr(obj, name):
            value = getattr(obj, name)
            if value not in (None, ""):
                return value
    return default


def write_audit(
    db: Session,
    vuln: Vulnerability,
    step: PipelineStatus,
    message: str,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        cve_id=vuln.cve_id,
        pipeline_step=step,
        message=(message or "")[:512],
        details=jsonable(details or {}),
    )
    db.add(entry)
    log.info("%s [%s] %s", vuln.cve_id, step.value, message)
    return entry


def set_status(
    db: Session,
    vuln: Vulnerability,
    status: PipelineStatus,
    *,
    waiting: bool = False,
) -> None:
    apply_status(vuln, status, waiting=waiting)
    db.add(vuln)


def begin_step(db: Session, vuln: Vulnerability, step: PipelineStatus, message: str) -> None:
    write_audit(db, vuln, step, message)
    db.flush()


def complete_step(
    db: Session,
    vuln: Vulnerability,
    step: PipelineStatus,
    message: str,
    details: dict[str, Any] | None = None,
) -> None:
    set_status(db, vuln, step)
    write_audit(db, vuln, step, message, details)
    db.commit()
    db.refresh(vuln)


def log_ai_fallback(
    db: Session,
    vuln: Vulnerability,
    message: str,
    details: dict[str, Any] | None = None,
) -> None:
    write_audit(db, vuln, PipelineStatus.AI_FALLBACK, message, details)
    if hasattr(vuln, "ai_extraction_used") and "extract" in message.lower():
        vuln.ai_extraction_used = True
    db.flush()


def fail_vulnerability(
    db: Session,
    vuln: Vulnerability | None,
    message: str,
    exc: BaseException | None = None,
) -> None:
    details: dict[str, Any] = {"error": message}
    if exc is not None:
        details["exception"] = type(exc).__name__
        details["traceback"] = traceback.format_exc()
    if vuln is None:
        log.error("Pipeline failed with no vulnerability row: %s", message)
        return
    if hasattr(vuln, "failure_reason"):
        vuln.failure_reason = message[:4000]
    set_status(db, vuln, PipelineStatus.FAILED)
    write_audit(db, vuln, PipelineStatus.FAILED, message, details)
    try:
        db.commit()
    except Exception:
        log.exception("Could not persist FAILED state for %s", vuln.cve_id)
        db.rollback()
