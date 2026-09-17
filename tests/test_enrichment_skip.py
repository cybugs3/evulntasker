from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from types import SimpleNamespace

from app.api.settings.integrations import EnrichmentIn
from app.config import Settings, get_settings
from app.db.session import Base
from app.models.enums import PipelineStatus
from app.models.pipeline import IngestEvent
from app.models.source import InputSource
from app.models.vulnerability import Vulnerability
from app.pipeline.step1_ingest import accept_cve
from app.pipeline.step3_enrich import apply_ingested_fields, enrich_cve, enrichment_gaps, intel_wait_message


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def test_enrichment_off_disables_nvd(monkeypatch):
    monkeypatch.setenv("ENRICHMENT_ENABLED", "false")
    monkeypatch.setenv("NVD_ENABLED", "true")
    get_settings.cache_clear()
    settings = Settings()
    assert settings.enrichment_enabled is False
    assert settings.nvd_enabled is True
    assert settings.nvd_configured is False
    get_settings.cache_clear()


def test_apply_ingested_fields_maps_json_aliases():
    vuln = Vulnerability(cve_id="CVE-2024-0001", title="CVE-2024-0001")
    applied = apply_ingested_fields(
        vuln,
        {
            "vendor": "Apache",
            "product": "HTTP Server",
            "cvss": 9.8,
            "epss": 0.71,
            "severity": "critical",
            "cwe": "CWE-79",
            "versions": ["2.4.49", "2.4.50"],
            "attackVector": "NETWORK",
            "summary": "Path traversal in Apache HTTP Server",
        },
    )
    assert "cvss_score" in applied
    assert vuln.vendor == "Apache"
    assert vuln.product == "HTTP Server"
    assert vuln.cvss_score == 9.8
    assert vuln.epss_score == 0.71
    assert vuln.severity == "CRITICAL"
    assert vuln.cwe_ids == ["CWE-79"]
    assert vuln.affected_versions == "2.4.49, 2.4.50"
    assert vuln.attack_vector == "NETWORK"
    assert "Path traversal" in vuln.description


def test_accept_cve_copies_scores_from_json():
    db = _session()
    source = InputSource(
        name="JSON webhook",
        source_type="web_api",
        description="",
        enabled=True,
        config={},
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    event = IngestEvent(
        source_id=source.id,
        payload={
            "cve_id": "CVE-2024-0001",
            "vendor": "OpenSSL",
            "product": "OpenSSL",
            "cvss_score": 7.5,
            "epss_score": 0.2,
        },
        raw_text="CVE-2024-0001",
        status="queued",
        extracted_cves=["CVE-2024-0001"],
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    vuln, created = accept_cve(db, event, source, "CVE-2024-0001")
    assert created == "created"
    assert vuln.vendor == "OpenSSL"
    assert vuln.cvss_score == 7.5
    assert vuln.epss_score == 0.2


async def test_enrich_cve_skips_external_calls_when_disabled(monkeypatch):
    monkeypatch.setenv("ENRICHMENT_ENABLED", "false")
    monkeypatch.setenv("NVD_ENABLED", "true")
    get_settings.cache_clear()

    async def boom(*_args, **_kwargs):
        raise AssertionError("external enrichment must not run")

    monkeypatch.setattr("app.pipeline.step3_enrich.NVDClient.lookup", boom)
    monkeypatch.setattr("app.pipeline.step3_enrich.EPSSClient.lookup", boom)
    monkeypatch.setattr("app.pipeline.step3_enrich.NVDClient.fetch", boom)
    monkeypatch.setattr("app.pipeline.step3_enrich.EPSSClient.fetch", boom)
    monkeypatch.setattr("app.pipeline.step3_enrich.AICopilot.enrich", boom)

    db = _session()
    vuln = Vulnerability(
        cve_id="CVE-2024-3094",
        title="CVE-2024-3094",
        pipeline_status="extracting",
        status=PipelineStatus.EXTRACTED,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)

    await enrich_cve(
        db,
        vuln,
        source_fields={
            "vendor": "XZ Utils",
            "product": "xz",
            "cvss_score": 10.0,
            "epss_score": 0.9,
        },
    )
    assert vuln.status == PipelineStatus.ENRICHED
    assert vuln.enrichment.get("skipped") is True
    assert vuln.vendor == "XZ Utils"
    assert vuln.product == "xz"
    assert vuln.cvss_score == 10.0
    assert vuln.severity == "CRITICAL"
    assert vuln.priority == "P1"
    get_settings.cache_clear()


async def test_enrich_cve_does_not_call_epss_when_disabled(monkeypatch):
    monkeypatch.setenv("ENRICHMENT_ENABLED", "true")
    monkeypatch.setenv("NVD_ENABLED", "false")
    monkeypatch.setenv("EPSS_ENABLED", "false")
    monkeypatch.setenv("AI_ENABLED", "false")
    get_settings.cache_clear()

    async def boom(*_args, **_kwargs):
        raise AssertionError("EPSS must not run until enabled")

    monkeypatch.setattr("app.pipeline.step3_enrich.EPSSClient.lookup", boom)
    monkeypatch.setattr("app.pipeline.step3_enrich.NVDClient.lookup", boom)
    monkeypatch.setattr("app.pipeline.step3_enrich.EPSSClient.fetch", boom)
    monkeypatch.setattr("app.pipeline.step3_enrich.NVDClient.fetch", boom)
    monkeypatch.setattr("app.pipeline.step3_enrich._intel_lookup_on", lambda *_a, **_k: False)

    db = _session()
    vuln = Vulnerability(
        cve_id="CVE-2026-52923",
        title="CVE-2026-52923",
        pipeline_status="extracting",
        status=PipelineStatus.EXTRACTED,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    await enrich_cve(db, vuln)
    assert vuln.status == PipelineStatus.ENRICHED
    assert vuln.enrichment.get("epss") is None
    get_settings.cache_clear()


async def test_enrich_cve_waits_when_nvd_has_no_data(monkeypatch):
    monkeypatch.setenv("ENRICHMENT_ENABLED", "true")
    monkeypatch.setenv("NVD_ENABLED", "true")
    monkeypatch.setenv("EPSS_ENABLED", "false")
    monkeypatch.setenv("AI_ENABLED", "false")
    get_settings.cache_clear()

    async def empty(*_args, **_kwargs):
        return None, None

    monkeypatch.setattr("app.pipeline.step3_enrich.NVDClient.lookup", empty)
    monkeypatch.setattr("app.pipeline.step3_enrich.EPSSClient.lookup", empty)
    monkeypatch.setattr("app.pipeline.step3_enrich._intel_lookup_on", lambda feed, *_a, **_k: feed == "nvd")

    db = _session()
    vuln = Vulnerability(
        cve_id="CVE-2024-4844",
        title="CVE-2024-4844",
        pipeline_status="extracting",
        status=PipelineStatus.EXTRACTED,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    await enrich_cve(db, vuln)
    assert vuln.status == PipelineStatus.ENRICHED
    assert vuln.pipeline_status == "waiting_enrichment"
    assert vuln.enrichment["waiting"] is True
    assert vuln.enrichment["wait_kind"] == "incomplete"
    assert "vendor" in vuln.enrichment["missing"]
    assert vuln.enrichment.get("retry_at")
    get_settings.cache_clear()


async def test_enrich_cve_timeout_stays_waiting_not_failed(monkeypatch):
    monkeypatch.setenv("ENRICHMENT_ENABLED", "true")
    monkeypatch.setenv("NVD_ENABLED", "true")
    monkeypatch.setenv("EPSS_ENABLED", "true")
    monkeypatch.setenv("AI_ENABLED", "false")
    get_settings.cache_clear()

    async def timed_out(*_args, **_kwargs):
        return None, "timeout"

    monkeypatch.setattr("app.pipeline.step3_enrich.NVDClient.lookup", timed_out)
    monkeypatch.setattr("app.pipeline.step3_enrich.EPSSClient.lookup", timed_out)
    monkeypatch.setattr("app.pipeline.step3_enrich._intel_lookup_on", lambda *_a, **_k: True)

    db = _session()
    vuln = Vulnerability(
        cve_id="CVE-2024-4844",
        title="CVE-2024-4844",
        pipeline_status="extracting",
        status=PipelineStatus.EXTRACTED,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    await enrich_cve(db, vuln)
    assert vuln.status == PipelineStatus.ENRICHED
    assert vuln.pipeline_status == "waiting_enrichment"
    assert vuln.enrichment["wait_kind"] == "timeout"
    assert "did not respond in time" in vuln.enrichment["wait_reason"]
    assert "NVD" in vuln.enrichment["wait_reason"]
    get_settings.cache_clear()


async def test_enrich_cve_continues_when_nvd_is_complete(monkeypatch):
    monkeypatch.setenv("ENRICHMENT_ENABLED", "true")
    monkeypatch.setenv("NVD_ENABLED", "true")
    monkeypatch.setenv("EPSS_ENABLED", "false")
    monkeypatch.setenv("AI_ENABLED", "false")
    get_settings.cache_clear()

    async def full(*_args, **_kwargs):
        return {
            "title": "Trellix ePO",
            "description": "An issue in ePO",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "severity": "HIGH",
            "vendor": "Trellix",
            "product": "ePolicy Orchestrator",
            "attack_vector": "NETWORK",
        }, None

    monkeypatch.setattr("app.pipeline.step3_enrich.NVDClient.lookup", full)
    async def empty(*_args, **_kwargs):
        return None, None

    monkeypatch.setattr("app.pipeline.step3_enrich.EPSSClient.lookup", empty)
    monkeypatch.setattr("app.pipeline.step3_enrich._intel_lookup_on", lambda feed, *_a, **_k: feed == "nvd")

    db = _session()
    vuln = Vulnerability(
        cve_id="CVE-2024-4844",
        title="CVE-2024-4844",
        pipeline_status="extracting",
        status=PipelineStatus.EXTRACTED,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    await enrich_cve(db, vuln)
    assert vuln.status == PipelineStatus.ENRICHED
    assert vuln.pipeline_status != "waiting_enrichment"
    assert not (vuln.enrichment or {}).get("waiting")
    assert vuln.vendor == "Trellix"
    assert vuln.cvss_score == 7.5
    get_settings.cache_clear()


def test_enrichment_gaps_follow_enabled_lookups(monkeypatch):
    vuln = Vulnerability(cve_id="CVE-1", title="x")
    settings = SimpleNamespace(enrichment_enabled=True)
    monkeypatch.setattr("app.pipeline.step3_enrich._intel_lookup_on", lambda feed, *_a, **_k: feed == "nvd")
    assert enrichment_gaps(vuln, settings) == ["vendor", "product", "cvss"]
    vuln.vendor = "Trellix"
    vuln.product = "ePO"
    vuln.cvss_score = 7.5
    assert enrichment_gaps(vuln, settings) == []
    monkeypatch.setattr("app.pipeline.step3_enrich._intel_lookup_on", lambda feed, *_a, **_k: feed == "epss")
    assert enrichment_gaps(vuln, settings) == ["epss"]
    settings = SimpleNamespace(enrichment_enabled=False)
    assert enrichment_gaps(vuln, settings) == []


def test_intel_wait_message_timeout_is_not_failed():
    kind, reason = intel_wait_message(["vendor", "cvss"], nvd_error="timeout", epss_error=None)
    assert kind == "timeout"
    assert "NVD" in reason
    assert "did not respond in time" in reason
    kind, reason = intel_wait_message(["epss"], nvd_error=None, epss_error="unreachable")
    assert kind == "timeout"
    assert "EPSS" in reason
    kind, reason = intel_wait_message(["vendor"], nvd_error=None, epss_error=None)
    assert kind == "incomplete"
    assert "vendor" in reason


def test_enrichment_payload_can_toggle_stage_only():
    stage = EnrichmentIn(enrichment_enabled=False)
    assert stage.enrichment_enabled is False
    assert stage.nvd_enabled is None
    assert stage.nvd_api_base is None
    intel = EnrichmentIn(nvd_enabled=True, nvd_api_base="https://example.invalid/nvd")
    assert intel.enrichment_enabled is None
    assert intel.nvd_enabled is True


def test_due_waiting_enrichment_finds_blob_without_dashboard_flag():
    from datetime import datetime, timedelta, timezone

    from app.pipeline.step3_enrich import due_waiting_enrichment

    db = _session()
    flagged = Vulnerability(
        cve_id="CVE-2026-0001",
        title="flagged",
        pipeline_status="waiting_enrichment",
        status=PipelineStatus.ENRICHED,
        enrichment={"waiting": True},
    )
    drifted = Vulnerability(
        cve_id="CVE-2026-0002",
        title="drifted",
        pipeline_status="enriching",
        status=PipelineStatus.EXTRACTED,
        enrichment={
            "waiting": True,
            "retry_at": (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat(),
        },
    )
    later = Vulnerability(
        cve_id="CVE-2026-0003",
        title="not yet",
        pipeline_status="waiting_enrichment",
        status=PipelineStatus.ENRICHED,
        enrichment={
            "waiting": True,
            "retry_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    )
    done = Vulnerability(
        cve_id="CVE-2026-0004",
        title="done",
        pipeline_status="matching",
        status=PipelineStatus.MATCHED,
        enrichment={},
    )
    db.add_all([flagged, drifted, later, done])
    db.commit()
    due_ids = {row.cve_id for row in due_waiting_enrichment(db)}
    assert due_ids == {"CVE-2026-0001", "CVE-2026-0002"}
