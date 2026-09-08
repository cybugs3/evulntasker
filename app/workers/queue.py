"""
In-process asyncio work queue.

This is the default execution backend for a single-node Linux service.
Events are persisted in `ingest_events` first (so nothing is lost on restart),
then the queue drains them. A Celery alternative lives in `app/workers/celery_app.py`.
"""

from __future__ import annotations

import asyncio
import logging

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

    def enqueue(self, event_id: int) -> None:
        if self._queue is None:
            # Lifespan has not started yet (e.g. tests enqueueing too early).
            log.warning("Queue not started; dropping event %s until worker starts", event_id)
            return
        self._queue.put_nowait(event_id)
        log.debug("Queued ingest event %s (qsize=%s)", event_id, self._queue.qsize())

    async def start(self) -> None:
        # Recreate loop-bound primitives so TestClient / reload reuse this singleton.
        self._queue = asyncio.Queue()
        self._stopping = asyncio.Event()
        self._rehydrate()
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

    def _rehydrate(self) -> None:
        """Pick up queued/processing events after a process restart."""
        db = SessionLocal()
        try:
            pending = (
                db.query(IngestEvent)
                .filter(IngestEvent.status.in_(("queued", "processing")))
                .all()
            )
            for event in pending:
                assert self._queue is not None
                self._queue.put_nowait(event.id)
            if pending:
                log.info("Rehydrated %s unfinished ingest event(s)", len(pending))
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
                self._queue.task_done()
        log.info("Pipeline worker stopped")


queue = InProcessQueue()
