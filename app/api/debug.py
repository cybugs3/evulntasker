"""Pipeline debugger API — run a CVE through traced stages."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.debug_trace import run_cve_debug

router = APIRouter()


class DebugRunIn(BaseModel):
    cve_id: str = Field(..., min_length=3, max_length=32)
    sample_text: str = ""
    persist: bool = True


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
            persist=body.persist,
        )
    except Exception as exc:
        raise HTTPException(500, f"Debug run failed: {exc}") from exc
