"""FIRST EPSS client — exploitation probability enrichment."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.config import get_settings
from app.integrations.nvd import lookup_error_kind

log = logging.getLogger(__name__)

_TRANSIENT = (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError)


class EPSSClient:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def fetch(self, cve_id: str) -> dict[str, Any] | None:
        data, _error = await self.lookup(cve_id)
        return data

    async def lookup(self, cve_id: str) -> tuple[dict[str, Any] | None, str | None]:
        from app.services.intel_sources import enabled_lookups

        sources = enabled_lookups("epss")
        if not sources:
            return None, None
        last_error: str | None = None
        for source in sources:
            try:
                parsed = await self._fetch_one(cve_id, source["endpoint"])
                if parsed:
                    return parsed, None
            except Exception as exc:
                last_error = lookup_error_kind(exc)
                log.exception("EPSS lookup failed for %s via %s (%s)", cve_id, source["endpoint"], last_error)
        return None, last_error

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        retry=retry_if_exception_type(_TRANSIENT),
    )
    async def _fetch_one(self, cve_id: str, endpoint: str) -> dict[str, Any] | None:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(
                endpoint,
                params={"cve": cve_id},
                headers={"User-Agent": "EVulnTasker/1.0"},
            )
            response.raise_for_status()
            payload = response.json()

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
