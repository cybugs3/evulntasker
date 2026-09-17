"""Ticketing provider abstraction — Jira, Monday.com, email, or custom REST CRM."""

from __future__ import annotations

import logging
from typing import Any, Protocol

from app.config import Settings, enabled_ticketing_providers, get_settings

log = logging.getLogger(__name__)


class TicketingClient(Protocol):
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
    ) -> dict[str, Any]: ...


def _client_for(provider: str, settings: Settings) -> TicketingClient:
    if provider == "monday":
        from app.integrations.ticketing.monday import MondayClient

        return MondayClient(settings)
    if provider == "custom":
        from app.integrations.ticketing.custom import CustomCrmClient

        return CustomCrmClient(settings)
    if provider == "email":
        from app.integrations.ticketing.mail import EmailTicketingClient

        return EmailTicketingClient(settings)
    from app.integrations.ticketing.jira import JiraTicketingClient

    return JiraTicketingClient(settings)


def get_ticketing_clients(settings: Settings | None = None) -> list[tuple[str, TicketingClient]]:
    settings = settings or get_settings()
    return [(name, _client_for(name, settings)) for name in enabled_ticketing_providers(settings)]


def get_ticketing_client(settings: Settings | None = None) -> TicketingClient:
    settings = settings or get_settings()
    clients = get_ticketing_clients(settings)
    if clients:
        return clients[0][1]
    provider = (getattr(settings, "ticketing_provider", None) or "jira").lower()
    return _client_for(provider, settings)
