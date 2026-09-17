from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.pipeline import IngestEvent
from app.models.repository import VulnerabilityRepository
from app.models.source import InputSource
from app.models.vulnerability import Vulnerability
from app.services.repo_catalog import repository_cve_counts


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def test_counts_stored_cves_and_enrichment_lookups():
    db = _session()
    local = InputSource(name="Local folder", source_type="local", description="", enabled=True)
    atom = InputSource(name="ATOM feeds", source_type="web_api", description="", enabled=True)
    db.add_all([local, atom])
    db.flush()

    local_repo = VulnerabilityRepository(
        name="Local folder",
        feed_type="local",
        endpoint="/tmp/intel",
        enabled=True,
        config={"source_managed": True, "source_id": local.id, "source_type": "local", "location_key": "path"},
    )
    atom_repo = VulnerabilityRepository(
        name="CISA Advisories",
        feed_type="atom",
        endpoint="https://www.cisa.gov/advisories.xml",
        enabled=True,
        config={"atom_managed": True, "url": "https://www.cisa.gov/advisories.xml"},
    )
    nvd = VulnerabilityRepository(
        name="NVD",
        feed_type="nvd",
        endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0",
        enabled=False,
        raw_count=280_000,
    )
    epss = VulnerabilityRepository(
        name="FIRST EPSS",
        feed_type="epss",
        endpoint="https://api.first.org/data/v1/epss",
        enabled=False,
        raw_count=280_000,
    )
    db.add_all([local_repo, atom_repo, nvd, epss])
    db.add_all(
        [
            Vulnerability(
                cve_id="CVE-2024-1111",
                source_name="Local folder",
                nvd_modified_at=datetime.now(timezone.utc),
                enrichment={"nvd": {"vendor": "opswat"}},
            ),
            Vulnerability(
                cve_id="CVE-2024-2222",
                source_name="ATOM feeds",
                epss_score=0.12,
                enrichment={"epss": {"epss_score": 0.12}},
            ),
            Vulnerability(cve_id="CVE-2024-3333", source_name="ATOM feeds"),
        ]
    )
    db.add_all(
        [
            IngestEvent(
                source_id=local.id,
                extracted_cves=["CVE-2024-1111"],
                payload={"cve_id": "CVE-2024-1111"},
            ),
            IngestEvent(
                source_id=atom.id,
                extracted_cves=["CVE-2024-2222", "CVE-2024-3333"],
                payload={
                    "cves": ["CVE-2024-2222", "CVE-2024-3333"],
                    "feed_url": "https://www.cisa.gov/advisories.xml",
                },
            ),
            IngestEvent(
                source_id=atom.id,
                extracted_cves=["CVE-1999-0001"],
                payload={"cves": ["CVE-1999-0001"], "feed_url": "https://www.cisa.gov/advisories.xml"},
            ),
        ]
    )
    db.commit()

    counts = repository_cve_counts(db, [local_repo, atom_repo, nvd, epss])
    assert counts[local_repo.id] == 1
    assert counts[atom_repo.id] == 2
    assert counts[nvd.id] == 1
    assert counts[epss.id] == 1
