import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.integrations.gmail import (
    format_epss_probability,
    gmail_configured,
    render_gmail_ticket_html,
    send_gmail_ticket,
)
from app.models.asset import Asset, AssetMatch
from app.models.enums import PipelineStatus
from app.models.vulnerability import Vulnerability
from app.pipeline.step5_act import take_action


def _settings(**kwargs):
    values = {
        "gmail_sender_email": "",
        "gmail_app_password": "",
        "gmail_receiver_email": "",
        "gmail_configured": False,
        "ticketing_provider": "jira",
        "ticketing_enabled": True,
        "jira_project_key": "VULN",
        "jira_hunt_project_key": "HUNT",
        "ticketing_hunt_email": "",
        "custom_owner_project": "VULN",
        "custom_hunt_project": "HUNT",
        "monday_board_id": "",
        "ticketing_fallback_owner_email": "",
    }
    values.update(kwargs)
    if "gmail_configured" not in kwargs:
        values["gmail_configured"] = bool(
            values["gmail_sender_email"]
            and values["gmail_app_password"]
            and values["gmail_receiver_email"]
        )
    return SimpleNamespace(**values)


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _vuln(**kwargs) -> Vulnerability:
    values = {
        "cve_id": "CVE-2024-1234",
        "title": "Remote code execution in httpd",
        "description": "An attacker can execute code on a vulnerable Apache httpd instance.",
        "severity": "HIGH",
        "cvss_score": 8.1,
        "epss_score": 0.42,
        "vendor": "Apache",
        "product": "httpd",
        "affected_versions": "2.4.0-2.4.59",
        "priority": "P1",
        "attack_vector": "NETWORK",
    }
    values.update(kwargs)
    return Vulnerability(**values)


def test_gmail_configured_requires_all_three_fields():
    assert gmail_configured(_settings()) is False
    assert gmail_configured(_settings(gmail_sender_email="me@gmail.com")) is False
    assert (
        gmail_configured(
            _settings(
                gmail_sender_email="me@gmail.com",
                gmail_app_password="abcd efgh ijkl mnop",
                gmail_receiver_email="me@gmail.com",
            )
        )
        is True
    )


def test_format_epss_probability():
    assert format_epss_probability(0.42) == "42.00%"
    assert format_epss_probability(None) == "n/a"


def test_render_gmail_ticket_html_includes_required_fields():
    db = _session()
    vuln = _vuln()
    asset = Asset(
        name="httpd-prod",
        vendor="Apache",
        product="httpd",
        version="2.4.58",
        owner_name="Alice",
        owner_email="alice@corp.local",
        team="Web",
    )
    db.add_all([vuln, asset])
    db.commit()
    db.refresh(vuln)
    db.refresh(asset)
    db.add(AssetMatch(vulnerability_id=vuln.id, asset_id=asset.id, method="local"))
    db.commit()
    db.refresh(vuln)

    html = render_gmail_ticket_html(
        vuln,
        detections={
            "sigma_rule": "title: Hunting — CVE-2024-1234",
            "kql": "DeviceProcessEvents | take 10",
            "xql": "dataset = xdr_data",
        },
    )
    assert "CVE-2024-1234" in html
    assert "Remote code execution in httpd" in html
    assert "8.1" in html
    assert "42.00%" in html
    assert "httpd-prod" in html
    assert "Apache httpd 2.4.58" in html
    assert "title: Hunting — CVE-2024-1234" in html
    assert "DeviceProcessEvents" in html
    assert "Apply the vendor security update" in html


def test_send_gmail_ticket_skips_when_unconfigured(monkeypatch):
    sent = AsyncMock()
    monkeypatch.setattr("app.integrations.gmail._aiosmtp_send", sent)
    result = asyncio.run(send_gmail_ticket(_vuln(), settings=_settings()))
    assert result["skipped"] is True
    sent.assert_not_called()


def test_send_gmail_ticket_uses_starttls_on_587(monkeypatch):
    sent = AsyncMock(return_value=({}, "ok"))
    monkeypatch.setattr("app.integrations.gmail._aiosmtp_send", sent)
    settings = _settings(
        gmail_sender_email="me@gmail.com",
        gmail_app_password="abcd efgh ijkl mnop",
        gmail_receiver_email="inbox@gmail.com",
    )
    result = asyncio.run(
        send_gmail_ticket(
            _vuln(),
            detections={"sigma_rule": "title: hunt"},
            settings=settings,
        )
    )
    assert result["ok"] is True
    assert result["to"] == "inbox@gmail.com"
    sent.assert_awaited_once()
    args, kwargs = sent.call_args
    message = args[0]
    assert kwargs["hostname"] == "smtp.gmail.com"
    assert kwargs["port"] == 587
    assert kwargs["start_tls"] is True
    assert kwargs["username"] == "me@gmail.com"
    assert kwargs["password"] == "abcdefghijklmnop"
    assert message["To"] == "inbox@gmail.com"
    bodies = [part.get_content() for part in message.iter_parts()]
    assert any("CVE-2024-1234" in body for body in bodies)


def test_send_gmail_ticket_failure_does_not_raise(monkeypatch):
    async def boom(*_args, **_kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr("app.integrations.gmail._aiosmtp_send", boom)
    settings = _settings(
        gmail_sender_email="me@gmail.com",
        gmail_app_password="secret",
        gmail_receiver_email="me@gmail.com",
    )
    result = asyncio.run(send_gmail_ticket(_vuln(), settings=settings))
    assert result["ok"] is False
    assert result["skipped"] is False
    assert "connection refused" in result["error"]


def test_take_action_continues_when_gmail_send_fails(monkeypatch):
    db = _session()
    vuln = _vuln()
    db.add(vuln)
    db.commit()
    db.refresh(vuln)

    settings = _settings(
        gmail_sender_email="me@gmail.com",
        gmail_app_password="secret",
        gmail_receiver_email="me@gmail.com",
    )
    monkeypatch.setattr("app.pipeline.step5_act.get_settings", lambda: settings)

    class FakeTicketing:
        async def create_issue(self, **kwargs):
            return {"key": "VULN-1", "url": "https://jira.example/VULN-1", "dry_run": True, "raw": {}}

    monkeypatch.setattr("app.pipeline.step5_act.get_ticketing_clients", lambda _s: [("jira", FakeTicketing())])
    monkeypatch.setattr(
        "app.pipeline.step5_act.ExchangeClient",
        lambda: SimpleNamespace(send=lambda **_k: None),
    )

    async def boom(*_args, **_kwargs):
        raise RuntimeError("smtp exploded")

    monkeypatch.setattr("app.pipeline.step5_act.send_gmail_ticket", boom)

    asyncio.run(take_action(db, vuln))
    db.commit()
    db.refresh(vuln)
    assert vuln.status == PipelineStatus.ACTIONED
    assert vuln.tickets
    assert vuln.detections
