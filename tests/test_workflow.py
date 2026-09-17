from app.services.workflow import display_state, station_journey, workflow_progress


def test_new_cve_starts_at_ingest():
    progress = workflow_progress("ingested")
    assert progress["current"] == "ingest"
    assert progress["column"] == "ingest"
    assert progress["done"] == []
    assert progress["waiting"] is False


def test_extraction_marks_ingest_done():
    progress = workflow_progress("extracting")
    assert progress["current"] == "extract"
    assert progress["done"] == ["ingest"]


def test_waiting_intel_pulses_enrichment_not_done():
    progress = workflow_progress("waiting_enrichment", waiting_intel=True)
    assert progress["current"] == "enrich"
    assert progress["done"] == ["ingest", "extract"]
    assert "enrich" not in progress["done"]
    assert progress["waiting"] is True


def test_enrichment_success_then_matching():
    progress = workflow_progress("matching", has_intel=True)
    assert progress["current"] == "match"
    assert progress["done"] == ["ingest", "extract", "enrich"]
    assert progress["unmatched"] is True
    assert progress["terminal"] is True


def test_unmatched_does_not_turn_actions_blue():
    progress = workflow_progress("matching", has_intel=True, has_match=False)
    assert progress["current"] == "match"
    assert "match" not in progress["done"]
    assert "act" not in progress["done"]


def test_match_success_turns_matching_blue():
    progress = workflow_progress("matching", has_intel=True, has_match=True)
    assert progress["current"] == "match"
    assert "match" in progress["done"]
    assert "act" not in progress["done"]
    assert progress["terminal"] is False


def test_completed_with_ticket_fills_every_station():
    progress = workflow_progress(
        "completed",
        has_intel=True,
        has_match=True,
        has_ticket=True,
    )
    assert progress["current"] is None
    assert progress["column"] == "act"
    assert progress["done"] == ["ingest", "extract", "enrich", "match", "act"]
    assert progress["terminal"] is True


def test_completed_unmatched_stays_on_matching():
    progress = workflow_progress("completed", has_intel=True, has_match=False)
    assert progress["current"] == "match"
    assert progress["column"] == "match"
    assert progress["unmatched"] is True
    assert "act" not in progress["done"]
    assert progress["terminal"] is True


def test_display_state_matches_live_workflow_labels():
    waiting = display_state(workflow_progress("waiting_enrichment", waiting_intel=True))
    assert waiting["filter_key"] == "waiting"
    assert waiting["station"] == "enrich"
    assert waiting["run_label"] == "Waiting for intel"

    miss = display_state(workflow_progress("matching", has_intel=True, has_match=False))
    assert miss["filter_key"] == "unmatched"
    assert miss["station"] == "match"
    assert miss["run_label"] == "Unmatched"

    done = display_state(
        workflow_progress("completed", has_intel=True, has_match=True, has_ticket=True)
    )
    assert done["filter_key"] == "completed"
    assert done["run_label"] == "Completed"

    stations = station_journey(workflow_progress("matching", has_intel=True, has_match=False))
    assert [row["id"] for row in stations] == ["ingest", "extract", "enrich", "match", "act"]
    assert stations[3]["status"] == "miss"
    assert stations[4]["status"] == "pending"


def test_station_journey_shows_timeout_wait_reason():
    progress = workflow_progress("waiting_enrichment", waiting_intel=True)
    progress["wait_reason"] = "NVD did not respond in time. Matching and tickets wait until NVD/EPSS return full data."
    progress["wait_kind"] = "timeout"
    stations = station_journey(progress)
    assert stations[2]["status"] == "waiting"
    assert "did not respond in time" in stations[2]["detail"]


def test_workflow_snapshot_groups_inflight_first():
    import app.models  # noqa: F401
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.session import Base
    from app.models.asset import Asset, AssetMatch
    from app.models.source import InputSource
    from app.models.vulnerability import Vulnerability
    from app.services.workflow import build_workflow_snapshot

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    db.add(InputSource(name="Local Folder", source_type="local"))
    fresh = Vulnerability(
        cve_id="CVE-2026-0101",
        title="new",
        pipeline_status="ingested",
        source_name="Local Folder",
    )
    done = Vulnerability(cve_id="CVE-2026-0102", title="old", pipeline_status="completed")
    db.add_all([fresh, done])
    db.commit()
    db.refresh(done)
    asset = Asset(
        name="ePO",
        vendor="Trellix",
        product="ePolicy Orchestrator",
        owner_name="Owner",
        owner_email="owner@example.com",
        team="Platform",
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    db.add(AssetMatch(vulnerability_id=done.id, asset_id=asset.id, method="local", confidence=1.0))
    db.commit()

    snapshot = build_workflow_snapshot(db)
    assert snapshot["stations"][0]["id"] == "ingest"
    ids = [row["cve_id"] for row in snapshot["cves"]]
    assert ids[0] == "CVE-2026-0101"
    assert snapshot["cves"][0]["current"] == "ingest"
    assert snapshot["cves"][0]["title"] == "new"
    assert snapshot["cves"][0]["source"]["name"] == "Local Folder"
    assert snapshot["cves"][0]["source"]["headline"] == "Local"
    assert snapshot["cves"][0]["matches"] == []
    assert snapshot["cves"][0]["tickets"] == []
    assert snapshot["summary"]["inflight"] == 1
    done_row = next(row for row in snapshot["cves"] if row["cve_id"] == "CVE-2026-0102")
    assert done_row["matches"][0]["name"] == "ePO"
    assert done_row["matches"][0]["owner_email"] == "owner@example.com"


def test_story_name_ignores_cve_id_title():
    from app.models.vulnerability import Vulnerability
    from app.services.workflow import _story_name

    vuln = Vulnerability(cve_id="CVE-2026-0101", title="CVE-2026-0101")
    assert _story_name(vuln) == ""


def test_ingest_origin_labels_channel_and_file():
    from app.services.workflow import ingest_origin

    inline = ingest_origin("inline", {"origin": "inline"})
    assert inline["headline"] == "Inline CVE"
    assert inline["kind_short"] == "Inline CVE"
    assert inline["detail"] == ""

    local = ingest_origin("local", {"filename": "/var/inbox/advisory.txt"})
    assert local["headline"] == "Local · advisory.txt"
    assert local["kind_short"] == "Local"
    assert local["filename"] == "advisory.txt"
    assert local["detail"] == "advisory.txt"

    hidden = ingest_origin("local", {"_origin_filename": "notes.md"})
    assert hidden["headline"] == "Local · notes.md"
    assert hidden["filename"] == "notes.md"

    smb = ingest_origin(
        "smb",
        {
            "filename": "cves.csv",
            "location": "fileserver\\intel",
            "smb_server": "fileserver",
            "smb_share": "intel",
        },
    )
    assert smb["headline"] == "SMB · fileserver\\intel · cves.csv"
    assert smb["kind_short"] == "SMB"
    assert smb["detail"] == "fileserver\\intel · cves.csv"

    atom = ingest_origin(
        "web_api",
        {"feed_name": "NVD", "feed_url": "https://nvd.nist.gov/feeds/xml/cve/misc.xml"},
    )
    assert atom["headline"] == "ATOM · NVD"
    assert atom["kind_short"] == "ATOM"
    assert atom["feed_name"] == "NVD"

    exchange = ingest_origin(
        "outlook",
        {"folder": "Inbox", "subject": "New CVE advisory"},
    )
    assert exchange["headline"] == "Exchange · Inbox · New CVE advisory"
    assert exchange["kind_short"] == "Exchange"


def test_workflow_snapshot_uses_ingest_event_origin():
    import app.models  # noqa: F401
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.session import Base
    from app.models.pipeline import IngestEvent, PipelineRun
    from app.models.source import InputSource
    from app.models.vulnerability import Vulnerability
    from app.services.workflow import build_workflow_snapshot

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    source = InputSource(name="Local folder", source_type="local")
    db.add(source)
    db.commit()
    db.refresh(source)
    vuln = Vulnerability(
        cve_id="CVE-2026-2222",
        title="from file",
        pipeline_status="ingested",
        source_name="Local folder",
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    event = IngestEvent(
        source_id=source.id,
        payload={"filename": "notes.md", "cves": ["CVE-2026-2222"]},
        extracted_cves=["CVE-2026-2222"],
        raw_text="CVE-2026-2222",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    db.add(PipelineRun(vulnerability_id=vuln.id, event_id=event.id, current_step="ingest"))
    db.commit()

    snapshot = build_workflow_snapshot(db)
    source_row = snapshot["cves"][0]["source"]
    assert source_row["headline"] == "Local · notes.md"
    assert source_row["kind_short"] == "Local"
    assert source_row["filename"] == "notes.md"
    assert source_row["detail"] == "notes.md"


def test_workflow_snapshot_plays_duplicate_at_extract():
    import app.models  # noqa: F401
    from datetime import datetime, timezone

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.session import Base
    from app.models.pipeline import IngestEvent
    from app.models.source import InputSource
    from app.models.vulnerability import Vulnerability
    from app.services.workflow import build_workflow_snapshot

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    source = InputSource(name="Inline CVE", source_type="inline")
    db.add(source)
    db.commit()
    db.refresh(source)
    vuln = Vulnerability(
        cve_id="CVE-2026-3333",
        title="known",
        pipeline_status="completed",
        source_name="Inline CVE",
    )
    db.add(vuln)
    db.commit()
    event = IngestEvent(
        source_id=source.id,
        payload={"cve_id": "CVE-2026-3333", "origin": "inline", "_duplicate": True},
        extracted_cves=["CVE-2026-3333"],
        status="skipped",
        received_at=datetime.now(timezone.utc),
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    snapshot = build_workflow_snapshot(db)
    play = next(row for row in snapshot["cves"] if row.get("duplicate"))
    assert play["play_key"] == f"dup-{event.id}-CVE-2026-3333"
    assert play["cve_id"] == "CVE-2026-3333"
    assert play["column"] == "extract"
    assert play["done"] == ["ingest"]
    assert play["terminal"] is True
    assert play["unmatched"] is False
    assert play["source"]["kind_short"] == "Inline CVE"
    catalog = next(row for row in snapshot["cves"] if row["cve_id"] == "CVE-2026-3333" and not row.get("duplicate"))
    assert catalog["column"] == "match"


def test_workflow_snapshot_plays_atom_refresh_through_actions():
    import app.models  # noqa: F401
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.session import Base
    from app.models.asset import Asset, AssetMatch
    from app.models.enums import PipelineStatus
    from app.models.pipeline import IngestEvent
    from app.models.source import InputSource
    from app.models.vulnerability import Vulnerability
    from app.services.workflow import build_workflow_snapshot

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    source = InputSource(name="ATOM feeds", source_type="web_api")
    db.add(source)
    db.commit()
    db.refresh(source)
    created = datetime.now(timezone.utc) - timedelta(days=2)
    vuln = Vulnerability(
        cve_id="CVE-2026-4444",
        title="from nvd",
        pipeline_status="completed",
        status=PipelineStatus.ACTIONED,
        cvss_score=8.0,
        vendor="Trellix",
        product="ePolicy Orchestrator",
        source_name="ATOM feeds",
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    vuln.created_at = created
    db.commit()
    asset = Asset(
        name="ePO",
        vendor="Trellix",
        product="ePolicy Orchestrator",
        owner_name="Owner",
        owner_email="owner@example.com",
        team="Platform",
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    db.add(AssetMatch(vulnerability_id=vuln.id, asset_id=asset.id, method="local", confidence=1.0))
    db.commit()
    event = IngestEvent(
        source_id=source.id,
        payload={
            "cve_id": "CVE-2026-4444",
            "feed_url": "https://nvd.nist.gov/feeds/xml/cve/misc.xml",
            "feed_name": "NVD",
            "_refresh": True,
        },
        extracted_cves=["CVE-2026-4444"],
        status="done",
        received_at=datetime.now(timezone.utc),
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    snapshot = build_workflow_snapshot(db)
    play = next(row for row in snapshot["cves"] if row.get("refreshed"))
    assert play["play_key"] == f"ref-{event.id}"
    assert play["cve_id"] == "CVE-2026-4444"
    assert play["refresh_label"] == "Updated from NVD"
    assert play["duplicate"] is not True
    assert play["column"] == "act"
    assert "extract" in play["done"]


def test_workflow_snapshot_plays_operator_rerun():
    import app.models  # noqa: F401
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.session import Base
    from app.models.pipeline import IngestEvent
    from app.models.source import InputSource
    from app.models.vulnerability import Vulnerability
    from app.services.workflow import build_workflow_snapshot

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    source = InputSource(name="Inline CVE", source_type="inline")
    db.add(source)
    db.commit()
    db.refresh(source)
    vuln = Vulnerability(
        cve_id="CVE-2023-46805",
        title="ics",
        pipeline_status="completed",
        source_name="Inline CVE",
        vendor="ivanti",
        product="connect secure",
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    vuln.created_at = datetime.now(timezone.utc) - timedelta(days=2)
    db.commit()
    event = IngestEvent(
        source_id=source.id,
        payload={
            "cve_id": "CVE-2023-46805",
            "origin": "inline",
            "_refresh": True,
            "_rerun": True,
        },
        extracted_cves=["CVE-2023-46805"],
        status="queued",
        received_at=datetime.now(timezone.utc),
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    snapshot = build_workflow_snapshot(db)
    play = next(row for row in snapshot["cves"] if row.get("refresh_label") == "Re-run")
    assert play["play_key"] == f"ref-{event.id}"
    assert play["cve_id"] == "CVE-2023-46805"
    assert play["refreshed"] is True
    assert play["duplicate"] is not True


def test_apply_status_writes_both_fields_together():
    from app.models.enums import PipelineStatus
    from app.models.vulnerability import Vulnerability
    from app.pipeline.state import apply_status

    vuln = Vulnerability(cve_id="CVE-2026-5555", title="sync")
    apply_status(vuln, PipelineStatus.EXTRACTED)
    assert vuln.status == PipelineStatus.EXTRACTED
    assert vuln.pipeline_status == "extracting"
    apply_status(vuln, PipelineStatus.ENRICHED, waiting=True)
    assert vuln.status == PipelineStatus.ENRICHED
    assert vuln.pipeline_status == "waiting_enrichment"
    apply_status(vuln, PipelineStatus.MATCHED)
    assert vuln.status == PipelineStatus.MATCHED
    assert vuln.pipeline_status == "matching"


def test_drifted_status_fields_classify_the_same():
    from app.models.enums import PipelineStatus
    from app.models.vulnerability import Vulnerability
    from app.services.workflow import canonical_pipeline_status, progress_for_vuln

    enum_ahead = Vulnerability(
        cve_id="CVE-2026-0101",
        title="enum ahead",
        status=PipelineStatus.ACTIONED,
        pipeline_status="ingested",
        cvss_score=8.0,
    )
    dash_ahead = Vulnerability(
        cve_id="CVE-2026-0102",
        title="dash ahead",
        status=PipelineStatus.INGESTED,
        pipeline_status="completed",
        cvss_score=8.0,
    )
    assert canonical_pipeline_status(enum_ahead) == "completed"
    assert canonical_pipeline_status(dash_ahead) == "completed"
    enum_progress = progress_for_vuln(enum_ahead)
    dash_progress = progress_for_vuln(dash_ahead)
    assert enum_progress["column"] == dash_progress["column"] == "match"
    assert enum_progress["unmatched"] is True
    assert dash_progress["unmatched"] is True
    matched = progress_for_vuln(enum_ahead, has_match=True, has_ticket=True)
    assert matched["column"] == "act"
    assert matched["unmatched"] is False


def test_waiting_blob_classifies_even_if_dashboard_string_drifted():
    from app.models.enums import PipelineStatus
    from app.models.vulnerability import Vulnerability
    from app.services.workflow import progress_for_vuln

    vuln = Vulnerability(
        cve_id="CVE-2026-0103",
        title="waiting blob",
        status=PipelineStatus.ENRICHED,
        pipeline_status="enriching",
        enrichment={"waiting": True},
    )
    progress = progress_for_vuln(vuln)
    assert progress["waiting"] is True
    assert progress["current"] == "enrich"

