"""
CMDB adapter.

Queries an internal CMDB for assets matching vendor / product. When the
CMDB is not configured, matching falls back to the local `assets` table.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import get_settings

log = logging.getLogger(__name__)


class CMDBClient:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.conn = self.settings.cmdb_connection

    async def find(self, vendor: str | None, product: str | None) -> list[dict[str, Any]]:
        if not (self.conn.configured and vendor):
            return []
        url = self.conn.base_url.rstrip("/") + "/assets"
        headers = {"User-Agent": "EVulnTasker/1.0", "Accept": "application/json", **self.conn.auth_headers()}
        auth = self.conn.auth_basic()
        try:
            async with httpx.AsyncClient(timeout=20.0, verify=self.conn.httpx_verify()) as client:
                response = await client.get(
                    url,
                    params={"vendor": vendor, "product": product or ""},
                    headers=headers,
                    auth=auth,
                )
                response.raise_for_status()
                data = response.json()
                return data if isinstance(data, list) else data.get("items") or []
        except Exception:
            log.exception("CMDB lookup failed")
            return []
