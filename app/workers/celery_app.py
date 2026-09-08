"""
Optional Celery application.

Use this when you need horizontal scale (multiple worker hosts) and a Redis
broker. The default deployment runs `InProcessQueue` inside uvicorn instead.

    celery -A app.workers.celery_app.celery worker -l info
"""

from __future__ import annotations

from celery import Celery

from app.config import get_settings

settings = get_settings()
celery = Celery(
    "evulntasker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)
celery.conf.update(task_serializer="json", accept_content=["json"], timezone="UTC")


@celery.task(name="evulntasker.run_event")
def run_event_task(event_id: int) -> None:
    import asyncio

    from app.db.session import SessionLocal
    from app.pipeline.orchestrator import PipelineOrchestrator

    db = SessionLocal()
    try:
        asyncio.run(PipelineOrchestrator(db).run_event(event_id))
    finally:
        db.close()
