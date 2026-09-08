from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.settings.integrations import EnrichmentIn
from app.config import Settings, get_settings
from app.db.session import Base
from app.models.enums import PipelineStatus
from app.models.pipeline import IngestEvent
from app.models.source import InputSource
from app.models.vulnerability import Vulnerability
from app.pipeline.step1_ingest import accept_cve
from app.pipeline.step3_enrich import apply_ingested_fields, enrich_cve


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

    monkeypatch.setattr("app.pipeline.step3_enrich.EPSSClient.fetch", boom)
    monkeypatch.setattr("app.pipeline.step3_enrich.NVDClient.fetch", boom)

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


def test_enrichment_payload_can_toggle_stage_only():
    stage = EnrichmentIn(enrichment_enabled=False)
    assert stage.enrichment_enabled is False
    assert stage.nvd_enabled is None
    assert stage.nvd_api_base is None
    intel = EnrichmentIn(nvd_enabled=True, nvd_api_base="https://example.invalid/nvd")
    assert intel.enrichment_enabled is None
    assert intel.nvd_enabled is True
