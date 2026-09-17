from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.db.session import Base
from app.models.audit import AuditLog
from app.models.enums import PipelineStatus
from app.models.vulnerability import Vulnerability
from app.services.ai_marks import clear_unconfigured_ai_marks


def _maker():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_clear_unconfigured_ai_marks_resets_flags_and_audit(monkeypatch):
    monkeypatch.setenv("AI_API_KEY", "")
    get_settings.cache_clear()
    Session = _maker()
    monkeypatch.setattr("app.services.ai_marks.SessionLocal", Session)
    db = Session()
    db.add(
        Vulnerability(
            cve_id="CVE-2024-3094",
            vendor="xz",
            product="xz",
            ai_extraction_used=True,
            ai_enrichment_used=True,
            ai_matching_used=True,
        )
    )
    db.add(
        AuditLog(
            cve_id="CVE-2024-3094",
            pipeline_step=PipelineStatus.AI_FALLBACK,
            message="old mark",
        )
    )
    db.add(
        AuditLog(
            cve_id="CVE-2024-3094",
            pipeline_step=PipelineStatus.EXTRACTED,
            message="keep",
        )
    )
    db.commit()
    db.close()

    changed = clear_unconfigured_ai_marks()
    assert changed >= 2

    db = Session()
    vuln = db.query(Vulnerability).one()
    assert vuln.ai_extraction_used is False
    assert vuln.ai_enrichment_used is False
    assert vuln.ai_matching_used is False
    steps = [row.pipeline_step for row in db.query(AuditLog).all()]
    assert PipelineStatus.AI_FALLBACK not in steps
    assert PipelineStatus.EXTRACTED in steps
    db.close()
    get_settings.cache_clear()


def test_clear_unconfigured_ai_marks_skips_when_key_present(monkeypatch):
    monkeypatch.setenv("AI_API_KEY", "real-key")
    get_settings.cache_clear()
    Session = _maker()
    monkeypatch.setattr("app.services.ai_marks.SessionLocal", Session)
    db = Session()
    db.add(
        Vulnerability(
            cve_id="CVE-2024-3094",
            ai_extraction_used=True,
        )
    )
    db.commit()
    db.close()

    assert clear_unconfigured_ai_marks() == 0
    db = Session()
    assert db.query(Vulnerability).one().ai_extraction_used is True
    db.close()
    get_settings.cache_clear()
