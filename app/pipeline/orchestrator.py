"""
Pipeline orchestrator — drives a single ingest event through the five steps.

  1. Ingest     (webhooks / Exchange / SMB / API feeds)
  2. Extract    (regex, then targeted AI fallback)
  3. Enrich     (NVD + EPSS, AI fallback for gaps; skippable via Settings)
  4. Match      (CMDB + Sonatype, AI fallback if unmatched)
  5. Act        (Jira, Sigma/SIEM, Exchange)

Each step writes AuditLog rows and updates Vulnerability.status.
Unrecoverable errors set status=FAILED and store the traceback on the log.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.pipeline import IngestEvent, PipelineRun
from app.models.source import InputSource
from app.models.vulnerability import Vulnerability
from app.pipeline.state import fail_vulnerability, pick
from app.pipeline.step1_ingest import accept_cve, start_event
from app.pipeline.step2_extract import extract_from_event, finalize_extract
from app.pipeline.step3_enrich import enrich_cve
from app.pipeline.step4_match import match_assets
from app.pipeline.step5_act import take_action

log = logging.getLogger(__name__)


def _ingest_fields(event: IngestEvent | None, extracted, cve_id: str) -> dict:
    payload = event.payload if event is not None and isinstance(getattr(event, "payload", None), dict) else {}
    merged = dict(payload)
    meta = (getattr(extracted, "per_cve", None) or {}).get(cve_id, {}) if extracted is not None else {}
    if isinstance(meta, dict):
        for key, value in meta.items():
            if value not in (None, ""):
                merged[key] = value
    return merged


class PipelineOrchestrator:
    def __init__(self, db: Session) -> None:
        self.db = db

    def _ai_enabled(self, source: InputSource | None) -> bool:
        if source is None:
            return True
        return bool(pick(source, "ai_fallback_enabled", "ai_fallback_enabled", default=True))

    def _stamp_run(self, run: PipelineRun, step: str, message: str) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "step": step,
            "message": message,
        }
        run.current_step = step
        run.log = list(run.log or []) + [entry]
        log.info("run=%s step=%s %s", run.id, step, message)

    async def run_event(self, event_id: int) -> None:
        event = self.db.get(IngestEvent, event_id)
        if event is None:
            log.error("Ingest event %s not found", event_id)
            return

        source = self.db.get(InputSource, event.source_id)
        ai_fallback = self._ai_enabled(source)
        run = PipelineRun(event_id=event.id, current_step="ingest", status="running", log=[])
        self.db.add(run)
        start_event(self.db, event, source)
        self.db.refresh(run)

        vuln: Vulnerability | None = None
        try:
            self._stamp_run(run, "extract", "Extracting CVE identifiers")
            extracted = await extract_from_event(event, ai_fallback=ai_fallback)
            event.extracted_cves = extracted.cve_ids
            self.db.commit()

            if not extracted.cve_ids:
                self.db.query(PipelineRun).filter(PipelineRun.event_id == event.id).delete()
                self.db.delete(event)
                self.db.commit()
                log.info("Dropped ingest event %s — no complete CVE ID", event_id)
                return

            kept_any = False
            refresh = bool(
                isinstance(getattr(event, "payload", None), dict)
                and (event.payload.get("feed_url") or event.payload.get("_refresh"))
            )
            for cve_id in extracted.cve_ids:
                try:
                    meta = extracted.per_cve.get(cve_id, {})
                    vuln, outcome = accept_cve(
                        self.db,
                        event,
                        source,
                        cve_id,
                        vendor=meta.get("vendor") or extracted.vendor,
                        product=meta.get("product") or extracted.product,
                        product_type=extracted.product_type,
                        versions=meta.get("versions") or extracted.versions,
                        summary=meta.get("summary") or extracted.summary,
                        ai_used=extracted.ai_used,
                        refresh=refresh,
                    )
                    run.vulnerability_id = vuln.id
                    self.db.commit()
                    if outcome == "skipped":
                        self._stamp_run(run, "ingest", f"{cve_id} already in database — skipping remaining steps")
                        continue
                    kept_any = True
                    source_fields = _ingest_fields(event, extracted, cve_id)
                    if outcome == "updated":
                        self._stamp_run(run, "ingest", f"{cve_id} updated from feed — refreshing enrichment")
                        await enrich_cve(
                            self.db, vuln, ai_fallback=ai_fallback, source_fields=source_fields
                        )
                        continue
                    await finalize_extract(self.db, vuln, extracted, cve_id)
                    await self._enrich_match_act(
                        run, vuln, ai_fallback=ai_fallback, source_fields=source_fields
                    )
                except Exception as exc:
                    log.exception("Pipeline failed for %s", cve_id)
                    fail_vulnerability(self.db, vuln, f"Unrecoverable pipeline error: {exc}", exc)
                    self._stamp_run(run, "failed", f"{cve_id} failed: {exc}")

            if not kept_any:
                self.db.query(PipelineRun).filter(PipelineRun.event_id == event.id).delete()
                self.db.delete(event)
                self.db.commit()
                log.info("Dropped ingest event %s — every CVE was already known", event_id)
                return

            event.status = "done"
            run.status = "completed"
            run.finished_at = datetime.now(timezone.utc)
            run.current_step = "complete"
            self.db.commit()
        except Exception as exc:
            log.exception("Pipeline failed for event %s", event_id)
            fail_vulnerability(self.db, vuln, f"Unrecoverable pipeline error: {exc}", exc)
            try:
                event = self.db.get(IngestEvent, event_id)
                run = self.db.get(PipelineRun, run.id) if run.id else None
                if event is not None:
                    event.status = "failed"
                    event.error = str(exc)
                if run is not None:
                    run.status = "failed"
                    run.finished_at = datetime.now(timezone.utc)
                    self._stamp_run(run, run.current_step or "unknown", f"Unhandled error: {exc}")
                self.db.commit()
            except Exception:
                log.exception("Could not persist event failure for %s", event_id)
                self.db.rollback()

    async def _enrich_match_act(
        self,
        run: PipelineRun,
        vuln: Vulnerability,
        ai_fallback: bool = True,
        source_fields: dict | None = None,
    ) -> None:
        """Public hook used by the reprocess API to resume from enrichment."""
        if source_fields is None and run.event_id:
            event = self.db.get(IngestEvent, run.event_id)
            source_fields = _ingest_fields(event, None, vuln.cve_id)
        if get_settings().enrichment_enabled:
            self._stamp_run(run, "enrich", f"Enriching {vuln.cve_id} via NVD/EPSS and/or AI")
        else:
            self._stamp_run(run, "enrich", f"Enrichment disabled — skipping to asset matching for {vuln.cve_id}")
        await enrich_cve(self.db, vuln, ai_fallback=ai_fallback, source_fields=source_fields)

        self._stamp_run(run, "match", f"Matching {vuln.cve_id} against organizational assets")
        await match_assets(self.db, vuln, ai_fallback=ai_fallback)

        self._stamp_run(run, "act", f"Opening Jira tasks and notifying owners for {vuln.cve_id}")
        await take_action(self.db, vuln)

        self._stamp_run(run, "complete", f"{vuln.cve_id} pipeline completed")
