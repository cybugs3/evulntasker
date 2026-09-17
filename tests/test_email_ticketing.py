import asyncio
import smtplib
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

    last, issues = asyncio.run(
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
    assert len(issues) == 2
    assert sorted(row["to"] for row in sent) == ["alice@corp.local", "bob@corp.local"]
    assert {t.assignee for t in vuln.tickets} == {"alice@corp.local", "bob@corp.local"}


def test_open_email_owner_tasks_skips_domains_outside_allow_list():
    db = _session()
    vuln = Vulnerability(cve_id="CVE-2024-1", vendor="Apache", product="httpd", severity="HIGH", priority="P1")
    inside = Asset(
        name="apache-prod",
        vendor="Apache",
        product="httpd",
        owner_email="alice@corp.local",
        owner_name="Alice",
        team="Web",
    )
    outside = Asset(
        name="libssl",
        vendor="OpenSSL",
        product="openssl",
        owner_email="eve@evil.example",
        owner_name="Eve",
        team="Other",
    )
    db.add_all([vuln, inside, outside])
    db.commit()
    db.refresh(vuln)
    db.refresh(inside)
    db.refresh(outside)
    db.add_all(
        [
            AssetMatch(vulnerability_id=vuln.id, asset_id=inside.id, method="local"),
            AssetMatch(vulnerability_id=vuln.id, asset_id=outside.id, method="local"),
        ]
    )
    db.commit()
    db.refresh(vuln)

    sent = []

    class FakeTicketing:
        async def create_issue(self, **kwargs):
            sent.append(kwargs)
            return {"key": "MAIL-owner", "url": f"mailto:{kwargs['to']}", "dry_run": False, "raw": {}}

    last, issues = asyncio.run(
        _open_email_owner_tasks(
            db,
            vuln,
            FakeTicketing(),
            "MAIL",
            existing_assignees=set(),
            domains=["corp.local"],
        )
    )
    assert last is not None
    assert len(issues) == 1
    assert [row["to"] for row in sent] == ["alice@corp.local"]


def test_rtl_mark_is_stripped_from_owner_email():
    from app.pipeline.step5_act import _clean_email

    dirty = "michaelelizarov15@gmail.com\u200f"
    assert _clean_email(dirty) == "michaelelizarov15@gmail.com"


def test_open_email_owner_tasks_keeps_going_if_one_mailbox_fails():
    db = _session()
    vuln = Vulnerability(cve_id="CVE-2024-1", vendor="linux", product="linux kernel", severity="HIGH", priority="P1")
    good = Asset(name="ubuntu", vendor="canonical", product="ubuntu", owner_email="alice@corp.local", owner_name="Alice", team="Linux")
    bad = Asset(
        name="glibc",
        vendor="gnu",
        product="glibc",
        owner_email="michaelelizarov15@gmail.com\u200f",
        owner_name="Lib",
        team="Libs",
    )
    db.add_all([vuln, good, bad])
    db.commit()
    db.refresh(vuln)
    db.refresh(good)
    db.refresh(bad)
    db.add_all(
        [
            AssetMatch(vulnerability_id=vuln.id, asset_id=good.id, method="csv"),
            AssetMatch(vulnerability_id=vuln.id, asset_id=bad.id, method="csv"),
        ]
    )
    db.commit()
    db.refresh(vuln)

    sent = []

    class FakeTicketing:
        async def create_issue(self, **kwargs):
            to = kwargs["to"]
            if to.startswith("michaelelizarov15"):
                raise RuntimeError("SMTP 555")
            sent.append(kwargs)
            return {"key": "MAIL-owner", "url": f"mailto:{to}", "dry_run": False, "raw": {}}

    last, issues = asyncio.run(
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
    assert [row["to"] for row in sent] == ["alice@corp.local"]
    assert len(issues) == 1
    assert {t.assignee for t in vuln.tickets} == {"alice@corp.local"}


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


def test_smtp_relay_strips_spaces_from_app_password():
    client = SmtpRelayClient(_settings(smtp_relay_password="abcd efgh ijkl mnop"))
    assert client.password == "abcdefghijklmnop"


def test_smtp_relay_gmail_plain_587_uses_starttls():
    client = SmtpRelayClient(
        _settings(
            smtp_relay_host="smtp.gmail.com",
            smtp_relay_port=587,
            smtp_relay_tls_mode="plain",
        )
    )
    assert client.mode == "starttls"


def test_smtp_relay_requires_password_when_username_set():
    client = SmtpRelayClient(
        _settings(
            smtp_relay_host="smtp.gmail.com",
            smtp_relay_port=587,
            smtp_relay_tls_mode="starttls",
            smtp_relay_username="evulntasker@gmail.com",
            smtp_relay_password="",
        )
    )
    try:
        client.probe()
    except RuntimeError as exc:
        assert "no password is stored" in str(exc)
    else:
        raise AssertionError("expected missing-password error")


def test_smtp_relay_starttls_then_login(monkeypatch):
    recorded: dict = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            recorded["host"] = host
            recorded["port"] = port
            recorded["steps"] = []

        def ehlo(self):
            recorded["steps"].append("ehlo")

        def starttls(self, context=None):
            recorded["steps"].append("starttls")

        def login(self, user, password):
            recorded["steps"].append(("login", user, password))

        def noop(self):
            return (250, b"ok")

        def quit(self):
            recorded["steps"].append("quit")

        def close(self):
            recorded["steps"].append("close")

    monkeypatch.setattr("app.integrations.smtp_relay.smtplib.SMTP", FakeSMTP)
    client = SmtpRelayClient(
        _settings(
            smtp_relay_host="smtp.gmail.com",
            smtp_relay_port=587,
            smtp_relay_tls_mode="starttls",
            smtp_relay_username="evulntasker@gmail.com",
            smtp_relay_password="abcd efgh ijkl mnop",
            smtp_relay_from="evulntasker@gmail.com",
        )
    )
    result = client.probe()
    assert recorded["host"] == "smtp.gmail.com"
    assert recorded["port"] == 587
    assert recorded["steps"][0] == "ehlo"
    assert "starttls" in recorded["steps"]
    assert ("login", "evulntasker@gmail.com", "abcdefghijklmnop") in recorded["steps"]
    assert result["ok"] is True
    assert result["password_set"] is True
    assert result["username"] == "evulntasker@gmail.com"


def test_smtp_relay_auth_error_names_the_login(monkeypatch):
    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            pass

        def ehlo(self):
            return None

        def starttls(self, context=None):
            return None

        def login(self, user, password):
            raise smtplib.SMTPAuthenticationError(535, b"BadCredentials")

        def close(self):
            return None

    monkeypatch.setattr("app.integrations.smtp_relay.smtplib.SMTP", FakeSMTP)
    client = SmtpRelayClient(
        _settings(
            smtp_relay_host="smtp.gmail.com",
            smtp_relay_port=587,
            smtp_relay_tls_mode="starttls",
            smtp_relay_username="evulntasker@gmail.com",
            smtp_relay_password="abcdefghijklmnop",
        )
    )
    try:
        client.probe()
    except RuntimeError as exc:
        assert "evulntasker@gmail.com" in str(exc)
        assert "username and password" in str(exc).lower()
    else:
        raise AssertionError("expected a named login error")


def test_smtp_test_recipient_prefers_username():
    client = SmtpRelayClient(
        _settings(
            smtp_relay_host="smtp.gmail.com",
            smtp_relay_username="guy.zwerdling@gmail.com",
            smtp_relay_from="evulntracker@gmail.com",
            ticketing_hunt_email="hunt@corp.local",
        )
    )
    assert client.test_recipient() == "guy.zwerdling@gmail.com"


def test_smtp_send_test_delivers_message(monkeypatch):
    recorded: dict = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            recorded["host"] = host

        def ehlo(self):
            return None

        def starttls(self, context=None):
            return None

        def login(self, user, password):
            recorded["login"] = user

        def send_message(self, message, from_addr=None, to_addrs=None):
            recorded["from"] = message["From"]
            recorded["to"] = message["To"]
            recorded["subject"] = message["Subject"]
            recorded["envelope_from"] = from_addr

        def quit(self):
            return None

        def close(self):
            return None

    monkeypatch.setattr("app.integrations.smtp_relay.smtplib.SMTP", FakeSMTP)
    client = SmtpRelayClient(
        _settings(
            smtp_relay_host="smtp.gmail.com",
            smtp_relay_port=587,
            smtp_relay_tls_mode="starttls",
            smtp_relay_username="guy.zwerdling@gmail.com",
            smtp_relay_password="abcdefghijklmnop",
            smtp_relay_from="evulntracker@gmail.com",
        )
    )
    result = client.send_test()
    assert result["sent"] is True
    assert result["to"] == "guy.zwerdling@gmail.com"
    assert recorded["from"] == "evulntracker@gmail.com"
    assert result["from"] == "evulntracker@gmail.com"
    assert recorded["to"] == "guy.zwerdling@gmail.com"
    assert recorded["subject"] == "[EVulnTasker] SMTP test"


def test_smtp_send_uses_from_address_on_gmail(monkeypatch):
    recorded: dict = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            return None

        def ehlo(self):
            return None

        def starttls(self, context=None):
            return None

        def login(self, user, password):
            return None

        def send_message(self, message, from_addr=None, to_addrs=None):
            recorded["header_from"] = message["From"]
            recorded["envelope_from"] = from_addr

        def quit(self):
            return None

        def close(self):
            return None

    monkeypatch.setattr("app.integrations.smtp_relay.smtplib.SMTP", FakeSMTP)
    client = SmtpRelayClient(
        _settings(
            smtp_relay_host="smtp.gmail.com",
            smtp_relay_port=587,
            smtp_relay_tls_mode="starttls",
            smtp_relay_username="guy.zwerdling@gmail.com",
            smtp_relay_password="abcdefghijklmnop",
            smtp_relay_from="alerts@corp.local",
        )
    )
    result = client.send(to="owner@corp.local", subject="Owner task", body="body")
    assert result["from"] == "alerts@corp.local"
    assert recorded["header_from"] == "alerts@corp.local"
    assert recorded["envelope_from"] == "guy.zwerdling@gmail.com"


def test_smtp_send_test_requires_recipient():
    client = SmtpRelayClient(_settings(smtp_relay_host="relay.corp.local"))
    try:
        client.send_test()
    except RuntimeError as exc:
        assert "no mailbox" in str(exc)
    else:
        raise AssertionError("expected missing recipient error")

