"""Clear leftover AI-used marks when no API key is configured."""

from __future__ import annotations

import logging

from sqlalchemy import or_

from app.config import get_settings
from app.db.session import SessionLocal
from app.models.audit import AuditLog
from app.models.enums import PipelineStatus
from app.models.vulnerability import Vulnerability

log = logging.getLogger(__name__)


def clear_unconfigured_ai_marks() -> int:
    """If there is no AI API key, strip AI flags and AI audit rows.

    Those marks meant "an LLM answered". Without a key nothing did.
    """
    if (get_settings().ai_api_key or "").strip():
        return 0
    db = SessionLocal()
    try:
        flagged = (
            db.query(Vulnerability)
            .filter(
                or_(
                    Vulnerability.ai_extraction_used.is_(True),
                    Vulnerability.ai_enrichment_used.is_(True),
                    Vulnerability.ai_matching_used.is_(True),
                )
            )
            .update(
                {
                    Vulnerability.ai_extraction_used: False,
                    Vulnerability.ai_enrichment_used: False,
                    Vulnerability.ai_matching_used: False,
                },
                synchronize_session=False,
            )
        )
        audits = (
            db.query(AuditLog)
            .filter(AuditLog.pipeline_step == PipelineStatus.AI_FALLBACK)
            .delete(synchronize_session=False)
        )
        db.commit()
        if flagged or audits:
            log.info("Cleared unconfigured AI marks: %s CVE flag(s), %s audit row(s)", flagged, audits)
        return int(flagged or 0) + int(audits or 0)
    except Exception:
        db.rollback()
        log.exception("Could not clear unconfigured AI marks")
        return 0
    finally:
        db.close()
