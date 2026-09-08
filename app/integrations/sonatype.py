"""
Sonatype (Nexus Lifecycle / IQ) adapter.

Looks up applications / components that match the enriched product so the
pipeline can attach the true application owner rather than a generic vendor.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import get_settings

log = logging.getLogger(__name__)


class SonatypeClient:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.conn = self.settings.sonatype_connection

    async def find(self, vendor: str | None, product: str | None) -> list[dict[str, Any]]:
        if not (self.conn.configured and product):
            return []
        url = self.conn.base_url.rstrip("/") + "/api/v2/applications"
        headers = {"User-Agent": "EVulnTasker/1.0", "Accept": "application/json", **self.conn.auth_headers()}
        auth = self.conn.auth_basic()
        try:
            async with httpx.AsyncClient(timeout=20.0, verify=self.conn.httpx_verify()) as client:
                response = await client.get(
                    url,
                    params={"product": product, "vendor": vendor or ""},
                    headers=headers,
                    auth=auth,
                )
                response.raise_for_status()
                data = response.json()
                return data if isinstance(data, list) else data.get("applications") or []
        except Exception:
            log.exception("Sonatype lookup failed")
            return []
