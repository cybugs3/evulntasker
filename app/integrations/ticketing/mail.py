"""Outbound email ticketing — SMTP mail relay, with Exchange as fallback."""

from __future__ import annotations

import logging
from typing import Any

from app.config import Settings
from app.integrations.exchange import ExchangeClient
from app.integrations.smtp_relay import SmtpRelayClient

log = logging.getLogger(__name__)

_PLACEHOLDER_MAIL = {"soc@example.com", "threat-hunting@example.com"}


class EmailTicketingClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _relay(self) -> SmtpRelayClient:
        return SmtpRelayClient(self.settings)

    @property
    def configured(self) -> bool:
        if not self.settings.ticketing_enabled:
            return False
        if self._relay().configured:
            return True
        return ExchangeClient.from_app().can_send()

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
        labels = labels or []
        kind = "hunt" if any("hunt" in str(item).lower() for item in labels) else "owner"
        recipient = (to or "").strip()
        if recipient.lower() in _PLACEHOLDER_MAIL:
            recipient = ""
        if not recipient and kind == "hunt":
            recipient = (self.settings.ticketing_hunt_email or "").strip()

        key = f"MAIL-{kind}"
        mailto = f"mailto:{recipient}" if recipient else ""
        if not self.configured or not recipient:
            log.info("Email dry-run: would send %s to %s — %s", key, recipient or "(no recipient)", summary)
            return {"key": key, "url": mailto or "mailto:", "dry_run": True, "raw": {"to": recipient}}

        relay = self._relay()
        if relay.configured:
            result = relay.send(to=[recipient], subject=summary[:200], body=description)
        else:
            result = ExchangeClient.from_app().send(
                to=[recipient], subject=summary[:200], body=description
            )
        return {
            "key": key,
            "url": mailto,
            "dry_run": bool(result.get("dry_run")),
            "raw": result,
        }
