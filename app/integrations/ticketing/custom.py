"""Generic REST CRM ticketing adapter for internal systems."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import Settings

log = logging.getLogger(__name__)


class CustomCrmClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def configured(self) -> bool:
        return self.settings.ticketing_connection.configured

    async def create_issue(
        self,
        *,
        project_key: str,
        summary: str,
        description: str,
        assignee: str | None = None,
        labels: list[str] | None = None,
        priority: str = "Medium",
        to: str | None = None,
    ) -> dict[str, Any]:
        conn = self.settings.ticketing_connection
        if not self.configured:
            key = f"{project_key}-DRY"
            log.info("Custom CRM dry-run: would create %s — %s", key, summary)
            return {"key": key, "url": f"{conn.base_url or 'https://crm.local'}/{key}", "dry_run": True, "raw": {}}

        url = conn.base_url.rstrip("/") + "/"
        payload = {
            "project": project_key,
            "summary": summary[:255],
            "description": description,
            "assignee": assignee,
            "labels": labels or ["evulntasker"],
            "priority": priority,
        }
        headers = {"User-Agent": "EVulnTasker/1.0", "Accept": "application/json", **conn.auth_headers()}
        auth = conn.auth_basic()
        async with httpx.AsyncClient(timeout=30.0, verify=conn.httpx_verify()) as client:
            response = await client.post(url, json=payload, headers=headers, auth=auth)
            response.raise_for_status()
            data = response.json() if response.content else {}
        key = data.get("key") or data.get("id") or f"{project_key}-NEW"
        return {
            "key": str(key),
            "url": data.get("url") or f"{conn.base_url}/{key}",
            "dry_run": False,
            "raw": data,
        }
