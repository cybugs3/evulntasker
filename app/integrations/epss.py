"""FIRST EPSS client — exploitation probability enrichment."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from app.config import get_settings

log = logging.getLogger(__name__)


class EPSSClient:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def fetch(self, cve_id: str) -> dict[str, Any] | None:
        from app.services.intel_sources import enabled_lookups

        sources = enabled_lookups("epss")
        if not sources:
            return None
        for source in sources:
            parsed = await self._fetch_one(cve_id, source["endpoint"])
            if parsed:
                return parsed
        return None

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
    async def _fetch_one(self, cve_id: str, endpoint: str) -> dict[str, Any] | None:
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(
                    endpoint,
                    params={"cve": cve_id},
                    headers={"User-Agent": "EVulnTasker/1.0"},
                )
                response.raise_for_status()
                payload = response.json()
        except Exception:
            log.exception("EPSS lookup failed for %s via %s", cve_id, endpoint)
            return None

        rows = payload.get("data") or []
        if not rows:
            return None
        row = rows[0]
        try:
            return {
                "epss_score": float(row.get("epss") or 0),
                "epss_percentile": float(row.get("percentile") or 0),
                "date": row.get("date"),
            }
        except (TypeError, ValueError):
            return None
