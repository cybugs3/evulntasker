"""Pipeline debugger API — run a CVE through traced stages."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import SessionLocal, get_db
from app.services.debug_trace import run_cve_debug
from app.utils.jsonutil import jsonable

router = APIRouter()


class DebugRunIn(BaseModel):
    cve_id: str = Field(..., min_length=3, max_length=32)
    sample_text: str = ""


@router.post("/debug/run")
async def debug_run(body: DebugRunIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    cve = (body.cve_id or "").strip()
    if not cve:
        raise HTTPException(400, "CVE ID is required")
    try:
        return await run_cve_debug(
            db,
            cve_id=cve,
            sample_text=body.sample_text or "",
        )
    except Exception as exc:
        raise HTTPException(500, f"Debug run failed: {exc}") from exc


@router.post("/debug/run/stream")
async def debug_run_stream(body: DebugRunIn) -> StreamingResponse:
    """NDJSON stream: begin → step (per station) → done | error."""
    cve = (body.cve_id or "").strip()
    if not cve:
        raise HTTPException(400, "CVE ID is required")

    async def gen():
        db = SessionLocal()
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

        def on_event(event: dict[str, Any]) -> None:
            queue.put_nowait(event)

        async def run() -> None:
            try:
                result = await run_cve_debug(
                    db,
                    cve_id=cve,
                    sample_text=body.sample_text or "",
                    on_event=on_event,
                )
                summary = {key: value for key, value in result.items() if key != "steps"}
                await queue.put({"type": "done", **summary})
            except Exception as exc:
                await queue.put({"type": "error", "message": str(exc)})
            finally:
                await queue.put(None)

        task = asyncio.create_task(run())
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield json.dumps(jsonable(item), default=str) + "\n"
        finally:
            await task
            db.close()

    return StreamingResponse(
        gen(),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
        },
    )
