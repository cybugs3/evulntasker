"""Jira REST API v3 ticketing adapter."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import Settings

log = logging.getLogger(__name__)


class JiraTicketingClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def configured(self) -> bool:
        return self.settings.jira_configured

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
        base = self.settings.ticketing_base_url
        if not self.configured:
            key = f"{project_key}-DRY"
            log.info("Jira dry-run: would create %s — %s", key, summary)
            return {
                "key": key,
                "url": f"{base or 'https://jira.local'}/browse/{key}",
                "dry_run": True,
                "raw": {},
            }

        payload: dict[str, Any] = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary[:255],
                "issuetype": {"name": self.settings.jira_issue_type},
                "description": _adf(description),
                "labels": labels or ["evulntasker"],
            }
        }
        if assignee:
            payload["fields"]["assignee"] = {"name": assignee}

        email = self.settings.jira_user_email or self.settings.ticketing_username
        token = self.settings.jira_api_token or self.settings.ticketing_password
        auth = (email, token)
        url = base.rstrip("/") + "/rest/api/3/issue"
        conn = self.settings.ticketing_connection
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=conn.httpx_verify()) as client:
                response = await client.post(url, json=payload, auth=auth)
                response.raise_for_status()
                data = response.json()
        except Exception:
            log.exception("Jira issue creation failed")
            raise

        key = data.get("key", "")
        return {
            "key": key,
            "url": f"{base.rstrip('/')}/browse/{key}",
            "dry_run": False,
            "raw": data,
        }


def _adf(text: str) -> dict[str, Any]:
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": text[:32000]}],
            }
        ],
    }
