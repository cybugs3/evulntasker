from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.db.session import Base
from app.models.asset import Asset
from app.models.enums import PipelineStatus
from app.models.vulnerability import Vulnerability
from app.pipeline.step3_enrich import apply_ai_enrichment, enrich_cve, inventory_context
from app.pipeline.step5_act import _hunt_description, _owner_description


NVD_BLOB = (
    "SysV IPC checkpoint restore next_id allocation can escape the valid IPC id "
    "range because ipc_idr_alloc used an open ended idr_alloc upper bound."
)
PLAIN = (
    "This is a Linux kernel bug in how the system hands out communication IDs. "
    "A local user can trigger a use-after-free, which can crash the host or "
    "raise their privileges to root. Red Hat Linux systems in inventory are "
    "likely affected — apply the kernel update and reboot."
)


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def test_apply_ai_enrichment_rewrites_nvd_wording():
    vuln = Vulnerability(
        cve_id="CVE-2026-52923",
        title="CVE-2026-52923",
        description=NVD_BLOB,
        vendor="Linux",
        product="Kernel",
        attack_vector="LOCAL",
        cwe_ids=["CWE-416"],
        enrichment={},
    )
    filled = apply_ai_enrichment(vuln, {"summary": PLAIN, "vendor": "ShouldNotReplace"})
    assert "description" in filled
    assert vuln.description == PLAIN
    assert vuln.vendor == "Linux"
    assert vuln.enrichment["source_description"] == NVD_BLOB
    assert vuln.enrichment["ai"]["summary"] == PLAIN


def test_apply_ai_enrichment_fills_identity_gaps():
    vuln = Vulnerability(cve_id="CVE-2026-52923", description=NVD_BLOB, enrichment={})
    filled = apply_ai_enrichment(
        vuln,
        {
            "vendor": "Red Hat",
            "product": "kernel",
            "product_type": "os",
            "versions": "el9 before 5.14.0-503",
            "summary": PLAIN,
        },
    )
    assert vuln.vendor == "Red Hat"
    assert vuln.product == "kernel"
    assert vuln.product_type == "os"
    assert vuln.affected_versions == "el9 before 5.14.0-503"
    assert vuln.description == PLAIN
    assert vuln.enrichment["ai"]["vendor"] == "Red Hat"
    assert "vendor" in filled
    assert "description" in filled


def test_apply_ai_enrichment_accepts_description_key():
    vuln = Vulnerability(cve_id="CVE-2026-52923", description=NVD_BLOB, enrichment={})
    filled = apply_ai_enrichment(vuln, {"description": PLAIN})
    assert "description" in filled
    assert vuln.description == PLAIN


def test_apply_ai_enrichment_keeps_text_without_summary():
    vuln = Vulnerability(cve_id="CVE-2026-52923", description=NVD_BLOB, enrichment={})
    filled = apply_ai_enrichment(vuln, {"vendor": "Linux", "description": NVD_BLOB})
    assert "description" not in filled
    assert vuln.description == NVD_BLOB
    assert vuln.vendor == "Linux"


def test_inventory_context_includes_redhat(tmp_path):
    db = _session()
    db.add(
        Asset(
            name="prod-rhel-01",
            vendor="Red Hat",
            product="Red Hat Enterprise Linux",
            version="9.4",
            system_type="os",
            active=True,
        )
    )
    db.commit()
    snapshot = inventory_context(db)
    assert any(row["vendor"] == "Red Hat" for row in snapshot)


def test_jira_body_leads_with_plain_description(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.mail_templates.template_path", lambda: tmp_path / "missing.json")
    vuln = Vulnerability(cve_id="CVE-2026-52923", description=PLAIN, severity="HIGH")
    payload = {
        "severity": "HIGH",
        "priority": "P2",
        "cvss_score": 7.8,
        "epss_score": 0.1,
        "attack_vector": "LOCAL",
        "vendor": "Linux",
        "product": "Kernel",
        "system_type": "os",
        "version": "9.4",
        "asset_name": "prod-rhel-01",
        "asset_owner": "Linux team",
        "username": "linux-ops",
        "email": "linux@example.com",
        "team": "Platform",
    }
    body = _owner_description(vuln, payload)
    assert body.index("What this vulnerability does") < body.index("Details")
    assert PLAIN in body
    hunt = _hunt_description(vuln, {"sigma_rule": "rule", "kql": "", "xql": "", "aqk": "", "ekql": ""})
    assert PLAIN in hunt


async def test_enrich_cve_calls_ai_when_fields_already_present(monkeypatch):
    monkeypatch.setenv("ENRICHMENT_ENABLED", "true")
    monkeypatch.setenv("NVD_ENABLED", "false")
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("AI_API_KEY", "test-key")
    monkeypatch.setenv("AI_ENRICHMENT_MODE", "direct")
    get_settings.cache_clear()
    captured: dict = {}

    class FakeCopilot:
        async def enrich(self, cve_id, partial):
            captured["cve_id"] = cve_id
            captured["partial"] = partial
            return {"summary": PLAIN}

    async def no_epss(self, *_args, **_kwargs):
        return None

    monkeypatch.setattr("app.pipeline.step3_enrich.AICopilot", lambda: FakeCopilot())
    monkeypatch.setattr("app.pipeline.step3_enrich.EPSSClient.fetch", no_epss)

    db = _session()
    db.add(
        Asset(
            name="prod-rhel-01",
            vendor="Red Hat",
            product="Red Hat Enterprise Linux",
            version="9.4",
            active=True,
        )
    )
    vuln = Vulnerability(
        cve_id="CVE-2026-52923",
        title="CVE-2026-52923",
        description=NVD_BLOB,
        vendor="Linux",
        product="Kernel",
        attack_vector="LOCAL",
        cwe_ids=["CWE-416"],
        pipeline_status="extracting",
        status=PipelineStatus.EXTRACTED,
        enrichment={},
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)

    await enrich_cve(db, vuln)
    assert captured["cve_id"] == "CVE-2026-52923"
    assert any(row.get("vendor") == "Red Hat" for row in captured["partial"]["inventory"])
    assert vuln.description == PLAIN
    assert vuln.ai_enrichment_used is True
    assert vuln.enrichment["source_description"] == NVD_BLOB
    get_settings.cache_clear()


async def test_enrich_cve_skips_ai_in_org_llm_mode(monkeypatch):
    monkeypatch.setenv("ENRICHMENT_ENABLED", "true")
    monkeypatch.setenv("NVD_ENABLED", "false")
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("AI_API_KEY", "test-key")
    monkeypatch.setenv("AI_ENRICHMENT_MODE", "org_llm")
    get_settings.cache_clear()

    async def boom(*_args, **_kwargs):
        raise AssertionError("AI must not run in org_llm mode")

    async def no_epss(self, *_args, **_kwargs):
        return None

    monkeypatch.setattr("app.pipeline.step3_enrich.AICopilot.enrich", boom)
    monkeypatch.setattr("app.pipeline.step3_enrich.EPSSClient.fetch", no_epss)

    db = _session()
    vuln = Vulnerability(
        cve_id="CVE-2026-52923",
        description=NVD_BLOB,
        vendor="Linux",
        product="Kernel",
        attack_vector="LOCAL",
        pipeline_status="extracting",
        status=PipelineStatus.EXTRACTED,
        enrichment={},
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    await enrich_cve(db, vuln)
    assert vuln.description == NVD_BLOB
    assert not vuln.ai_enrichment_used
    get_settings.cache_clear()
