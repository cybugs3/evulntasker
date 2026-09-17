import asyncio
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.enums import PipelineStatus
from app.models.pipeline import IngestEvent, PipelineRun
from app.models.vulnerability import Vulnerability
from app.pipeline.step5_act import take_action
from app.services.debug_trace import run_cve_debug


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _vuln(**kwargs) -> Vulnerability:
    values = {
        "cve_id": "CVE-2024-4844",
        "title": "Hardcoded credentials",
        "description": "Trellix ePO hardcoded credentials",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "vendor": "Trellix",
        "product": "ePolicy Orchestrator",
        "priority": "P2",
        "attack_vector": "NETWORK",
    }
    values.update(kwargs)
    return Vulnerability(**values)


def test_take_action_audit_false_skips_audit_log(monkeypatch):
    db = _session()
    vuln = _vuln()
    db.add(vuln)
    db.commit()
    db.refresh(vuln)

    monkeypatch.setattr(
        "app.pipeline.step5_act.get_settings",
        lambda: SimpleNamespace(
            ticketing_hunt_email="",
            ticketing_fallback_owner_email="",
            jira_project_key="VULN",
            jira_hunt_project_key="HUNT",
            custom_owner_project="VULN",
            custom_hunt_project="HUNT",
            monday_board_id="",
        ),
    )

    class FakeTicketing:
        async def create_issue(self, **kwargs):
            return {"key": "VULN-1", "url": "https://jira.example/VULN-1", "dry_run": True, "raw": {}}

    monkeypatch.setattr("app.pipeline.step5_act.get_ticketing_clients", lambda _s: [("jira", FakeTicketing())])
    monkeypatch.setattr(
        "app.pipeline.step5_act.ExchangeClient",
        lambda: SimpleNamespace(send=lambda **_k: None),
    )
    monkeypatch.setattr("app.pipeline.step5_act.gmail_configured", lambda _s: False)

    result = asyncio.run(take_action(db, vuln, audit=False, store=True))
    db.commit()
    db.refresh(vuln)

    assert result["issues"]
    assert result["issues"][0]["key"] == "VULN-1"
    assert vuln.status == PipelineStatus.ACTIONED
    assert vuln.tickets
    assert db.query(AuditLog).count() == 0


def _debug_settings(**kwargs):
    values = {
        "enrichment_enabled": True,
        "intel_start_date": "2020-01-01",
        "nvd_api_base": "https://nvd.example",
        "epss_api_base": "https://epss.example",
        "ai_enabled": False,
        "ai_configured": False,
        "ai_enrichment_direct": False,
        "ai_enrichment_mode": "direct",
        "ai_provider": "",
        "ai_model": "",
        "ai_api_base": "",
        "ticketing_enabled": True,
        "ticketing_email_enabled": True,
        "ticketing_jira_enabled": False,
        "ticketing_monday_enabled": False,
        "ticketing_custom_enabled": False,
        "ticketing_hunt_email": "hunt@example.com",
        "ticketing_fallback_owner_email": "",
        "gmail_sender_email": "",
        "gmail_app_password": "",
        "gmail_receiver_email": "",
    }
    values.update(kwargs)
    return SimpleNamespace(**values)


class _FakeNVD:
    async def fetch(self, cve_id):
        return {
            "cve_id": cve_id,
            "title": "Hardcoded credentials",
            "description": "Hardcoded credentials in Trellix ePolicy Orchestrator",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "severity": "HIGH",
            "attack_vector": "NETWORK",
            "attack_complexity": "HIGH",
            "privileges_required": "LOW",
            "user_interaction": "NONE",
            "vendor": "Trellix",
            "product": "ePolicy Orchestrator",
            "affected_versions": "All versions below ePO 5.10 Service Pack 1 Update 2",
            "cwe_ids": ["CWE-798"],
            "published_at": None,
            "nvd_modified_at": None,
        }

    async def lookup(self, cve_id):
        return await self.fetch(cve_id), None


class _FakeEPSS:
    async def fetch(self, cve_id):
        return None

    async def lookup(self, cve_id):
        return None, None


def _patch_debug_lookups(monkeypatch, settings=None):
    monkeypatch.setattr("app.services.debug_trace.NVDClient", _FakeNVD)
    monkeypatch.setattr("app.services.debug_trace.EPSSClient", _FakeEPSS)
    monkeypatch.setattr("app.services.debug_trace.lookup_active", lambda _name: True)
    monkeypatch.setattr("app.services.debug_trace.list_source_specs", lambda _s: [])
    monkeypatch.setattr("app.services.debug_trace.get_settings", lambda: settings or _debug_settings())
    monkeypatch.setattr("app.services.debug_trace.allow_cve", lambda _cve: True)


def test_debug_run_explains_match_and_does_not_send(monkeypatch):
    db = _session()
    db.add(
        Asset(
            name="ePO",
            vendor="trellix",
            product="epo",
            version="5.10.0",
            owner_name="Guy",
            owner_email="owner@example.com",
            team="Platform",
            active=True,
            source="local",
        )
    )
    db.commit()

    async def boom(*_a, **_k):
        raise AssertionError("take_action must not run from Debugger")

    _patch_debug_lookups(monkeypatch)
    monkeypatch.setattr("app.pipeline.step5_act.take_action", boom)

    result = asyncio.run(run_cve_debug(db, cve_id="CVE-2024-4844", persist=True))
    assert result["ok"] is True
    assert result["persisted"] is False
    assert result["relevant"] is True
    assert result["tickets"] == []
    assert result["ticketing_plan"]["sent"] is False
    owners = [item for item in result["ticketing_plan"]["would_notify"] if item["kind"] == "owner"]
    hunts = [item for item in result["ticketing_plan"]["would_notify"] if item["kind"] == "hunt"]
    assert owners[0]["to"] == "owner@example.com"
    assert hunts[0]["to"] == "hunt@example.com"
    assert "ePO" in result["match_lesson"]
    match_step = next(item for item in result["steps"] if item["step"] == 6)
    assert any("Matched `ePO`" in line for line in match_step["breakdown"])
    ticket_step = next(item for item in result["steps"] if item["title"] == "Ticketing")
    assert "Nothing sent" in ticket_step["summary"]
    assert any("never opens a ticket" in line for line in ticket_step["breakdown"])
    assert all(item.get("breakdown") for item in result["steps"])
    assert db.query(IngestEvent).count() == 0
    assert db.query(PipelineRun).count() == 0
    assert db.query(AuditLog).count() == 0
    assert db.query(Vulnerability).count() == 0


def test_debug_run_explains_why_no_match(monkeypatch):
    db = _session()
    _patch_debug_lookups(monkeypatch)

    result = asyncio.run(run_cve_debug(db, cve_id="CVE-2024-4844", persist=False))
    assert result["ok"] is True
    assert result["relevant"] is False
    assert result["tickets"] == []
    assert "empty" in (result["match_lesson"] or "").lower()
    match_step = next(item for item in result["steps"] if item["step"] == 6)
    assert any("empty" in line.lower() for line in match_step["breakdown"])
    owners = [item for item in result["ticketing_plan"]["would_notify"] if item["kind"] == "owner"]
    assert owners == []
    hunts = [item for item in result["ticketing_plan"]["would_notify"] if item["kind"] == "hunt"]
    assert hunts[0]["to"] == "hunt@example.com"


def test_debug_emits_working_indicator_before_each_step(monkeypatch):
    db = _session()
    events: list[dict] = []
    _patch_debug_lookups(monkeypatch)

    asyncio.run(run_cve_debug(db, cve_id="CVE-2024-4844", persist=False, on_event=events.append))
    begins = [event for event in events if event.get("type") == "begin"]
    steps = [event for event in events if event.get("type") == "step"]
    assert events[0]["type"] == "begin"
    assert events[0]["step"] == 1
    assert events[0]["status"] == "run"
    assert any(event["title"] == "Static internet enrichment" for event in begins)
    assert any(event["title"] == "Ticketing" for event in begins)
    assert [event["step"] for event in begins]
    for begin in begins:
        assert any(step["step"] == begin["step"] and step["type"] == "step" for step in steps)


def test_debug_stops_cve_before_intel_start(monkeypatch):
    db = _session()
    monkeypatch.setattr(
        "app.services.debug_trace.get_settings",
        lambda: _debug_settings(intel_start_date="2024-01-01"),
    )
    monkeypatch.setattr("app.services.debug_trace.allow_cve", lambda _cve: False)

    result = asyncio.run(run_cve_debug(db, cve_id="CVE-2022-0121", persist=False))
    assert result["ok"] is False
    assert result["stopped_at"] == 2
    assert result["cve_id"] == "CVE-2022-0121"
    assert db.query(Vulnerability).count() == 0
    step = next(item for item in result["steps"] if item["step"] == 2)
    assert step["status"] == "fail"
    assert "ignored" in step["summary"].lower() or "outside" in step["summary"].lower()
    assert any("INTEL_START_DATE" in line for line in step["breakdown"])
