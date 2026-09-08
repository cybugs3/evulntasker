"""Generic webhook listener — any JSON body is accepted and queued."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.source import InputSource
from app.services.ingestion import ingest_payload

router = APIRouter()


@router.post("/webhooks/{token}")
async def webhook_ingest(token: str, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    source = (
        db.query(InputSource)
        .filter(InputSource.webhook_token == token, InputSource.source_type == "webhook")
        .one_or_none()
    )
    if source is None:
        raise HTTPException(404, "Unknown webhook token")
    if not source.enabled:
        raise HTTPException(409, "Source is paused")

    raw = await request.body()
    payload: dict[str, Any]
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            payload = {"data": payload}
    except Exception:
        payload = {"raw": raw.decode("utf-8", errors="replace")}

    event = ingest_payload(db, source, payload=payload, raw_text=raw.decode("utf-8", errors="replace"))
    if event is None:
        return {"status": "ignored", "reason": "no complete CVE ID found", "source": source.name}
    return {"status": "queued", "event_id": event.id, "source": source.name}
