"""Monday.com GraphQL ticketing adapter."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import Settings, enabled_ticketing_providers

log = logging.getLogger(__name__)

MONDAY_API = "https://api.monday.com/v2"


class MondayClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def configured(self) -> bool:
        if "monday" not in enabled_ticketing_providers(self.settings):
            return False
        token = self.settings.ticketing_password or self.settings.jira_api_token
        return bool(token and self.settings.monday_board_id)

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
        board_id = self.settings.monday_board_id
        if not self.configured:
            key = f"MON-{project_key}-DRY"
            log.info("Monday dry-run: would create %s — %s", key, summary)
            return {"key": key, "url": f"https://monday.com/boards/{board_id or 'dry'}", "dry_run": True, "raw": {}}

        group_id = self.settings.monday_group_id or "topics"
        query = """
        mutation ($board: ID!, $group: String!, $name: String!) {
          create_item (board_id: $board, group_id: $group, item_name: $name) { id }
        }
        """
        token = self.settings.ticketing_password or self.settings.jira_api_token
        headers = {"Authorization": token, "Content-Type": "application/json"}
        body = {
            "query": query,
            "variables": {"board": board_id, "group": group_id, "name": summary[:255]},
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(MONDAY_API, json=body, headers=headers)
            response.raise_for_status()
            data = response.json()
        item_id = ((data.get("data") or {}).get("create_item") or {}).get("id", "")
        key = f"MON-{item_id or project_key}"
        return {
            "key": key,
            "url": f"https://monday.com/boards/{board_id}/pulses/{item_id}",
            "dry_run": False,
            "raw": data,
        }
