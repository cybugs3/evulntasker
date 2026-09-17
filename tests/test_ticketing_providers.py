from types import SimpleNamespace

from app.config import enabled_ticketing_providers
from app.integrations.ticketing import get_ticketing_client, get_ticketing_clients
from app.integrations.ticketing.jira import JiraTicketingClient
from app.integrations.ticketing.mail import EmailTicketingClient
from app.integrations.ticketing.monday import MondayClient


def _settings(**kwargs):
    values = {
        "ticketing_enabled": False,
        "ticketing_provider": "jira",
        "ticketing_jira_enabled": False,
        "ticketing_monday_enabled": False,
        "ticketing_email_enabled": False,
        "ticketing_custom_enabled": False,
    }
    values.update(kwargs)
    return SimpleNamespace(**values)


def test_legacy_single_provider_still_counts():
    settings = _settings(ticketing_enabled=True, ticketing_provider="email")
    assert enabled_ticketing_providers(settings) == ["email"]


def test_per_provider_flags_override_legacy():
    settings = _settings(
        ticketing_enabled=True,
        ticketing_provider="jira",
        ticketing_email_enabled=True,
        ticketing_monday_enabled=True,
    )
    assert enabled_ticketing_providers(settings) == ["monday", "email"]


def test_all_off_when_nothing_enabled():
    assert enabled_ticketing_providers(_settings()) == []


def test_get_ticketing_clients_returns_each_enabled():
    settings = _settings(ticketing_jira_enabled=True, ticketing_email_enabled=True)
    clients = get_ticketing_clients(settings)
    assert [name for name, _client in clients] == ["jira", "email"]
    assert isinstance(clients[0][1], JiraTicketingClient)
    assert isinstance(clients[1][1], EmailTicketingClient)


def test_get_ticketing_client_prefers_first_enabled():
    settings = _settings(ticketing_monday_enabled=True, ticketing_email_enabled=True)
    client = get_ticketing_client(settings)
    assert isinstance(client, MondayClient)
