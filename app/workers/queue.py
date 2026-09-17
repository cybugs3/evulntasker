"""
In-process asyncio work queue.

This is the default execution backend for a single-node Linux service.
Events are persisted in `ingest_events` first (so nothing is lost on restart),
then the queue drains them. A Celery alternative lives in `app/workers/celery_app.py`.

Feed pollers run in APScheduler worker threads. ``asyncio.Queue`` is not
thread-safe, so ``enqueue`` hops onto the pipeline event loop.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timezone

from app.config import get_settings
from app.db.session import SessionLocal
from app.models.pipeline import IngestEvent
from app.pipeline.orchestrator import PipelineOrchestrator

log = logging.getLogger(__name__)


class InProcessQueue:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[int] | None = None
        self._task: asyncio.Task | None = None
        self._stopping: asyncio.Event | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._pending: set[int] = set()
        self._lock = threading.Lock()

    def enqueue(self, event_id: int) -> None:
        if not self._claim(event_id):
            return
        loop = self._loop
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if loop is not None and loop.is_running() and running is not loop:
            loop.call_soon_threadsafe(self._put, event_id)
            log.info("Queued ingest event %s from feed poller", event_id)
            return
        self._put(event_id)

    def _claim(self, event_id: int) -> bool:
        with self._lock:
            if self._queue is None:
                log.warning("Queue not started; dropping event %s until worker starts", event_id)
                return False
            if event_id in self._pending:
                return False
            self._pending.add(event_id)
            return True

    def _put(self, event_id: int) -> None:
        if self._queue is None:
            return
        self._queue.put_nowait(event_id)
        log.debug("Queued ingest event %s (qsize=%s)", event_id, self._queue.qsize())

    def _release(self, event_id: int) -> None:
        with self._lock:
            self._pending.discard(event_id)

    async def start(self) -> None:
        # Recreate loop-bound primitives so TestClient / reload reuse this singleton.
        self._queue = asyncio.Queue()
        self._stopping = asyncio.Event()
        self._loop = asyncio.get_running_loop()
        with self._lock:
            self._pending.clear()
        self._rehydrate(include_processing=True)
        self._task = asyncio.create_task(self._worker(), name="evulntasker-pipeline-worker")

    async def stop(self) -> None:
        if self._stopping is not None:
            self._stopping.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            except RuntimeError:
                log.debug("Queue stop hit a closed event loop; ignoring")
            self._task = None
        self._queue = None
        self._stopping = None
        self._loop = None
        with self._lock:
            self._pending.clear()

    def _rehydrate(self, *, include_processing: bool = True) -> None:
        """Pick up queued events that never reached the worker (restart or missed enqueue)."""
        statuses = ("queued", "processing") if include_processing else ("queued",)
        db = SessionLocal()
        try:
            pending = (
                db.query(IngestEvent)
                .filter(IngestEvent.status.in_(statuses))
                .all()
            )
            n = 0
            for event in pending:
                if not self._claim(event.id):
                    continue
                self._put(event.id)
                n += 1
            if n:
                log.info("Rehydrated %s unfinished ingest event(s)", n)
        finally:
            db.close()

    async def _worker(self) -> None:
        settings = get_settings()
        log.info("Pipeline worker started")
        assert self._queue is not None
        assert self._stopping is not None
        while not self._stopping.is_set():
            try:
                event_id = await asyncio.wait_for(
                    self._queue.get(), timeout=settings.worker_poll_seconds
                )
            except TimeoutError:
                self._rehydrate(include_processing=False)
                await self._retry_waiting_enrichment()
                continue
            except asyncio.CancelledError:
                break
            db = SessionLocal()
            try:
                await PipelineOrchestrator(db).run_event(event_id)
            except Exception:
                log.exception("Worker crashed while processing event %s", event_id)
            finally:
                db.close()
                self._release(event_id)
                self._queue.task_done()
            await self._retry_waiting_enrichment()
        log.info("Pipeline worker stopped")

    async def _retry_waiting_enrichment(self) -> None:
        from app.models.pipeline import PipelineRun
        from app.models.vulnerability import Vulnerability
        from app.pipeline.step3_enrich import due_waiting_enrichment, is_enrichment_waiting

        db = SessionLocal()
        try:
            due = due_waiting_enrichment(db)
            ids = [vuln.id for vuln in due]
        except Exception:
            log.exception("Could not list CVEs waiting for enrichment")
            db.close()
            return
        db.close()
        for vuln_id in ids:
            session = SessionLocal()
            try:
                vuln = session.get(Vulnerability, vuln_id)
                if vuln is None or not is_enrichment_waiting(vuln):
                    continue
                run = PipelineRun(
                    vulnerability_id=vuln.id,
                    current_step="enrich",
                    status="running",
                    log=[],
                )
                session.add(run)
                session.commit()
                await PipelineOrchestrator(session)._enrich_match_act(run, vuln)
                session.refresh(vuln)
                run.status = "waiting_enrichment" if is_enrichment_waiting(vuln) else "completed"
                if run.status == "completed":
                    run.finished_at = datetime.now(timezone.utc)
                    run.current_step = "complete"
                session.commit()
            except Exception:
                log.exception("Enrichment retry failed for vulnerability %s", vuln_id)
            finally:
                session.close()


queue = InProcessQueue()
