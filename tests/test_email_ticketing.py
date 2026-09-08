import asyncio
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.integrations.smtp_relay import SmtpRelayClient
from app.integrations.ticketing import get_ticketing_client
from app.integrations.ticketing.mail import EmailTicketingClient
from app.models.asset import Asset, AssetMatch
from app.models.vulnerability import Vulnerability
from app.pipeline.step5_act import (
    _mail_ticket_key,
    _matched_owner_groups,
    _open_email_owner_tasks,
    _payload_for_owner_group,
)


def _settings(**kwargs):
    values = {
        "ticketing_enabled": True,
        "ticketing_provider": "email",
        "ticketing_hunt_email": "hunt@corp.local",
        "ticketing_fallback_owner_email": "soc@corp.local",
        "smtp_relay_host": "",
        "smtp_relay_port": 25,
        "smtp_relay_tls_mode": "plain",
        "smtp_relay_username": "",
        "smtp_relay_password": "",
        "smtp_relay_from": "",
        "smtp_relay_ignore_cert": False,
    }
    values.update(kwargs)
    return SimpleNamespace(**values)


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _asset(**kwargs) -> SimpleNamespace:
    values = {
        "name": "system",
        "owner_email": "",
        "owner_name": "",
        "owner_username": "",
        "team": "",
        "active": True,
        "vendor": "Apache",
        "product": "httpd",
        "version": "2.4",
        "system_type": "web",
    }
    values.update(kwargs)
    return SimpleNamespace(**values)


def test_email_client_dry_run_without_mailbox(monkeypatch):
    class FakeExchange:
        def can_send(self):
            return False

        def send(self, **_kwargs):
            raise AssertionError("must not send when mailbox is not configured")

    monkeypatch.setattr(
        "app.integrations.ticketing.mail.ExchangeClient.from_app",
        lambda: FakeExchange(),
    )
    client = EmailTicketingClient(_settings())
    assert client.configured is False
    result = asyncio.run(client.create_issue(
        project_key="MAIL",
        summary="[High] CVE-2024-1 — openssl",
        description="Patch openssl",
        labels=["evulntasker", "owner-action"],
        to="owner@corp.local",
    ))
    assert result["dry_run"] is True
    assert result["key"] == "MAIL-owner"


def test_email_client_sends_owner_and_hunt(monkeypatch):
    sent = []

    class FakeExchange:
        def can_send(self):
            return True

        def send(self, *, to, subject, body):
            sent.append({"to": to, "subject": subject, "body": body})
            return {"dry_run": False, "to": to, "subject": subject}

    monkeypatch.setattr(
        "app.integrations.ticketing.mail.ExchangeClient.from_app",
        lambda: FakeExchange(),
    )
    client = EmailTicketingClient(_settings())
    owner = asyncio.run(client.create_issue(
        project_key="MAIL",
        summary="Owner task",
        description="Owner body",
        labels=["owner-action"],
        to="alice@corp.local",
    ))
    hunt = asyncio.run(client.create_issue(
        project_key="MAIL",
        summary="Hunt task",
        description="Hunt body",
        labels=["threat-hunting"],
        to="hunt@corp.local",
    ))
    assert owner["dry_run"] is False
    assert owner["url"] == "mailto:alice@corp.local"
    assert hunt["key"] == "MAIL-hunt"
    assert [row["to"] for row in sent] == [["alice@corp.local"], ["hunt@corp.local"]]


def test_email_owner_without_to_does_not_use_fallback(monkeypatch):
    sent = []

    class FakeExchange:
        def can_send(self):
            return True

        def send(self, **kwargs):
            sent.append(kwargs)
            return {"dry_run": False}

    monkeypatch.setattr(
        "app.integrations.ticketing.mail.ExchangeClient.from_app",
        lambda: FakeExchange(),
    )
    client = EmailTicketingClient(_settings())
    result = asyncio.run(client.create_issue(
        project_key="MAIL",
        summary="Owner task",
        description="Owner body",
        labels=["owner-action"],
    ))
    assert result["dry_run"] is True
    assert sent == []


def test_email_hunt_uses_hunt_setting_when_to_omitted(monkeypatch):
    sent = []

    class FakeExchange:
        def can_send(self):
            return True

        def send(self, *, to, subject, body):
            sent.append({"to": to})
            return {"dry_run": False}

    monkeypatch.setattr(
        "app.integrations.ticketing.mail.ExchangeClient.from_app",
        lambda: FakeExchange(),
    )
    client = EmailTicketingClient(_settings())
    asyncio.run(client.create_issue(
        project_key="MAIL",
        summary="Hunt task",
        description="Hunt body",
        labels=["threat-hunting"],
    ))
    assert sent == [{"to": ["hunt@corp.local"]}]


def test_get_ticketing_client_email():
    settings = _settings()
    client = get_ticketing_client(settings)
    assert isinstance(client, EmailTicketingClient)


def test_matched_owner_groups_one_mail_per_owner():
    alice_apache = _asset(name="apache-prod", owner_email="alice@corp.local", owner_name="Alice", team="Web")
    alice_nginx = _asset(name="nginx-edge", owner_email="Alice@corp.local", owner_name="Alice", team="Web")
    bob = _asset(
        name="openssl-lib",
        owner_email="bob@corp.local",
        owner_name="Bob",
        team="Crypto",
        vendor="OpenSSL",
        product="openssl",
        version="3.0",
    )
    orphan = _asset(name="orphan", owner_email="")
    inactive = _asset(name="retired", owner_email="old@corp.local", active=False)
    vuln = SimpleNamespace(
        matches=[
            SimpleNamespace(asset=alice_apache),
            SimpleNamespace(asset=alice_nginx),
            SimpleNamespace(asset=bob),
            SimpleNamespace(asset=orphan),
            SimpleNamespace(asset=inactive),
        ]
    )
    groups = _matched_owner_groups(vuln)
    by_email = {g["email"].lower(): g for g in groups}
    assert set(by_email) == {"alice@corp.local", "bob@corp.local"}
    assert [a.name for a in by_email["alice@corp.local"]["assets"]] == ["apache-prod", "nginx-edge"]
    payload = _payload_for_owner_group(
        SimpleNamespace(cve_id="CVE-1", severity="HIGH", priority="P1", cvss_score=8, epss_score=0.1, attack_vector="NETWORK", vendor="Apache", product="httpd", product_type="web", affected_versions="2.4"),
        by_email["alice@corp.local"],
    )
    assert "apache-prod" in payload["asset_name"]
    assert "nginx-edge" in payload["asset_name"]
    assert payload["email"] == "alice@corp.local"


def test_matched_owner_groups_fallback_only_for_blank_email():
    owned = _asset(name="httpd", owner_email="alice@corp.local")
    blank = _asset(name="legacy", owner_email="")
    vuln = SimpleNamespace(matches=[SimpleNamespace(asset=owned), SimpleNamespace(asset=blank)])
    groups = _matched_owner_groups(vuln, fallback_email="soc@corp.local")
    by_email = {g["email"].lower(): g for g in groups}
    assert set(by_email) == {"alice@corp.local", "soc@corp.local"}
    assert [a.name for a in by_email["soc@corp.local"]["assets"]] == ["legacy"]


def test_mail_ticket_keys_differ_for_same_local_part():
    assert _mail_ticket_key("owner", "alice@web.local") != _mail_ticket_key("owner", "alice@db.local")
    assert len(_mail_ticket_key("owner", "alice@web.local")) <= 32


def test_open_email_owner_tasks_mails_each_internal_system_owner():
    db = _session()
    vuln = Vulnerability(cve_id="CVE-2024-1", vendor="Apache", product="httpd", severity="HIGH", priority="P1")
    apache = Asset(name="apache-prod", vendor="Apache", product="httpd", version="2.4", owner_email="alice@corp.local", owner_name="Alice", team="Web")
    openssl = Asset(name="libssl", vendor="OpenSSL", product="openssl", version="3.0", owner_email="bob@corp.local", owner_name="Bob", team="Crypto")
    db.add_all([vuln, apache, openssl])
    db.commit()
    db.refresh(vuln)
    db.refresh(apache)
    db.refresh(openssl)
    db.add_all(
        [
            AssetMatch(vulnerability_id=vuln.id, asset_id=apache.id, method="local"),
            AssetMatch(vulnerability_id=vuln.id, asset_id=openssl.id, method="local"),
        ]
    )
    db.commit()
    db.refresh(vuln)

    sent = []

    class FakeTicketing:
        async def create_issue(self, **kwargs):
            sent.append(kwargs)
            return {"key": "MAIL-owner", "url": f"mailto:{kwargs['to']}", "dry_run": False, "raw": {}}

    last = asyncio.run(
        _open_email_owner_tasks(
            db,
            vuln,
            FakeTicketing(),
            "MAIL",
            existing_assignees=set(),
        )
    )
    db.commit()
    db.refresh(vuln)
    assert last is not None
    assert sorted(row["to"] for row in sent) == ["alice@corp.local", "bob@corp.local"]
    assert {t.assignee for t in vuln.tickets} == {"alice@corp.local", "bob@corp.local"}


def test_smtp_relay_preferred_over_exchange(monkeypatch):
    sent = []

    class FakeRelay:
        configured = True

        def send(self, *, to, subject, body):
            sent.append({"to": to, "subject": subject, "body": body})
            return {"dry_run": False, "to": to, "subject": subject}

    class BoomExchange:
        def can_send(self):
            raise AssertionError("Exchange must not be used when SMTP relay is set")

        def send(self, **_kwargs):
            raise AssertionError("Exchange must not send when SMTP relay is set")

    monkeypatch.setattr(
        "app.integrations.ticketing.mail.SmtpRelayClient",
        lambda _settings: FakeRelay(),
    )
    monkeypatch.setattr(
        "app.integrations.ticketing.mail.ExchangeClient.from_app",
        lambda: BoomExchange(),
    )
    client = EmailTicketingClient(_settings(smtp_relay_host="relay.lab.local"))
    assert client.configured is True
    result = asyncio.run(client.create_issue(
        project_key="MAIL",
        summary="Owner task",
        description="Owner body",
        labels=["owner-action"],
        to="alice@external.example",
    ))
    assert result["dry_run"] is False
    assert sent == [{"to": ["alice@external.example"], "subject": "Owner task", "body": "Owner body"}]


def test_smtp_relay_client_not_configured_without_host():
    client = SmtpRelayClient(_settings(smtp_relay_host=""))
    assert client.configured is False
    result = client.send(to="alice@corp.local", subject="x", body="y")
    assert result["dry_run"] is True

