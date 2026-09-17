from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.pipeline import enrichment_queue, extraction_queue
from app.db.session import Base
from app.models.enums import PipelineStatus
from app.models.pipeline import IngestEvent
from app.models.source import InputSource
from app.models.vulnerability import Vulnerability


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def test_extraction_queue_keeps_cves_after_they_leave_extract(monkeypatch):
    monkeypatch.setattr("app.api.pipeline._cleaned_ingest_noise", True)
    db = _session()
    db.add(
        Vulnerability(
            cve_id="CVE-2024-1111",
            status=PipelineStatus.ACTIONED,
            source_name="Local folder",
        )
    )
    db.add(
        Vulnerability(
            cve_id="CVE-2024-2222",
            status=PipelineStatus.ENRICHED,
            source_name="Local folder",
        )
    )
    db.commit()
    payload = extraction_queue(db, include_rows=True)
    ids = {row["cve_id"] for row in payload["rows"]}
    assert ids == {"CVE-2024-1111", "CVE-2024-2222"}
    assert payload["kpis"]["cves"] == 2


def test_extraction_queue_lists_each_local_file(monkeypatch):
    monkeypatch.setattr("app.api.pipeline._cleaned_ingest_noise", True)
    db = _session()
    source = InputSource(name="Local folder", source_type="local", description="", enabled=True, config={})
    db.add(source)
    db.commit()
    db.refresh(source)
    db.add(
        IngestEvent(
            source_id=source.id,
            payload={"filename": "input1.txt", "cves": ["CVE-2026-1111"]},
            raw_text="CVE-2026-1111",
            status="done",
            extracted_cves=["CVE-2026-1111"],
        )
    )
    db.add(
        IngestEvent(
            source_id=source.id,
            payload={"filename": "input2.txt", "cves": ["CVE-2026-1111", "CVE-2022-0121"]},
            raw_text="CVE-2026-1111 CVE-2022-0121",
            status="done",
            extracted_cves=["CVE-2026-1111", "CVE-2022-0121"],
        )
    )
    db.commit()
    payload = extraction_queue(db, include_rows=True)
    names = [row["filename"] for row in payload["events"]]
    assert "input1.txt" in names
    assert "input2.txt" in names
    input2 = next(row for row in payload["events"] if row["filename"] == "input2.txt")
    assert "CVE-2022-0121" in input2["cves"]


def test_extraction_queue_collapses_same_filename(monkeypatch):
    monkeypatch.setattr("app.api.pipeline._cleaned_ingest_noise", True)
    db = _session()
    source = InputSource(name="Local folder", source_type="local", description="", enabled=True, config={})
    db.add(source)
    db.commit()
    db.refresh(source)
    db.add(
        IngestEvent(
            source_id=source.id,
            payload={"filename": "input2.txt", "cves": ["CVE-2022-0121"]},
            raw_text="CVE-2022-0121",
            status="skipped",
            extracted_cves=["CVE-2022-0121"],
        )
    )
    db.add(
        IngestEvent(
            source_id=source.id,
            payload={"filename": "input2.txt", "cves": ["CVE-2022-0121", "CVE-2025-38003", "CVE-2026-85103"]},
            raw_text="CVE-2022-0121 CVE-2025-38003 CVE-2026-85103",
            status="done",
            extracted_cves=["CVE-2022-0121", "CVE-2025-38003", "CVE-2026-85103"],
        )
    )
    db.commit()
    payload = extraction_queue(db, include_rows=True)
    files = [row["filename"] for row in payload["events"]]
    assert files.count("input2.txt") == 1
    row = next(item for item in payload["events"] if item["filename"] == "input2.txt")
    assert row["status"] == "done"
    assert row["cves"] == ["CVE-2022-0121", "CVE-2025-38003", "CVE-2026-85103"]


def test_enrichment_queue_keeps_cves_after_enrich():
    db = _session()
    db.add(
        Vulnerability(
            cve_id="CVE-2024-3333",
            status=PipelineStatus.ACTIONED,
            vendor="Apache",
            product="httpd",
            cvss_score=7.5,
            enrichment={"nvd": {"id": "CVE-2024-3333"}},
        )
    )
    db.commit()
    payload = enrichment_queue(db, include_rows=True)
    assert [row["cve_id"] for row in payload["rows"]] == ["CVE-2024-3333"]
    assert payload["rows"][0]["intel"] is True
    assert payload["kpis"]["enriched"] == 1


def test_enrichment_queue_lists_cves_older_than_intel_start():
    db = _session()
    db.add(
        Vulnerability(
            cve_id="CVE-2022-0121",
            status=PipelineStatus.ENRICHED,
            source_name="Local folder",
        )
    )
    db.commit()
    payload = enrichment_queue(db, include_rows=True)
    assert [row["cve_id"] for row in payload["rows"]] == ["CVE-2022-0121"]


def test_matching_kpis_follow_live_workflow():
    from app.api.pipeline import matching_queue
    from app.models.asset import Asset, AssetMatch
    from app.services.workflow import build_workflow_snapshot

    db = _session()
    ingested = Vulnerability(cve_id="CVE-2026-0001", title="new", pipeline_status="ingested")
    enriching = Vulnerability(
        cve_id="CVE-2026-0002",
        title="intel",
        status=PipelineStatus.ENRICHED,
        pipeline_status="enriching",
        cvss_score=9.8,
        vendor="Vendor",
        product="App",
    )
    unmatched = Vulnerability(
        cve_id="CVE-2026-0003",
        title="miss",
        status=PipelineStatus.MATCHED,
        pipeline_status="matching",
        cvss_score=7.5,
        vendor="Other",
        product="Thing",
    )
    completed_miss = Vulnerability(
        cve_id="CVE-2026-0004",
        title="old miss",
        status=PipelineStatus.ACTIONED,
        pipeline_status="completed",
        cvss_score=5.0,
        vendor="Ghost",
        product="App",
    )
    hit = Vulnerability(
        cve_id="CVE-2026-0005",
        title="hit",
        status=PipelineStatus.ACTIONED,
        pipeline_status="completed",
        cvss_score=8.0,
        vendor="Trellix",
        product="ePolicy Orchestrator",
    )
    db.add_all([ingested, enriching, unmatched, completed_miss, hit])
    db.commit()
    db.refresh(hit)
    asset = Asset(name="ePO", vendor="Trellix", product="ePolicy Orchestrator")
    db.add(asset)
    db.commit()
    db.refresh(asset)
    db.add(AssetMatch(vulnerability_id=hit.id, asset_id=asset.id, method="local", confidence=1.0))
    db.commit()

    matching = matching_queue(db, include_rows=True)
    workflow = build_workflow_snapshot(db)
    assert matching["kpis"]["unmatched"] == workflow["summary"]["unmatched"] == 2
    assert matching["kpis"]["matched"] == 1
    ids = {row["cve_id"] for row in matching["rows"]}
    assert ids == {"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"}
    assert "CVE-2026-0001" not in ids
    assert "CVE-2026-0002" not in ids
    miss_rows = [row for row in matching["rows"] if row["unmatched"]]
    assert {row["cve_id"] for row in miss_rows} == {"CVE-2026-0003", "CVE-2026-0004"}

