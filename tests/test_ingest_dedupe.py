from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.settings.common import cleanup_input_sources
from app.db.session import Base
from app.models.pipeline import IngestEvent
from app.models.source import InputSource
from app.services.ingestion import (
    InlineIngestError,
    _delete_events_by_id,
    ingest_inline_cve,
    ingest_payload,
    purge_duplicate_ingest_events,
    purge_unconfigured_atom_events,
    queue_cve_rerun,
)


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _source(db, name="ATOM feeds", source_type="web_api", config=None):
    source = InputSource(
        name=name,
        source_type=source_type,
        description="",
        enabled=False,
        config=config or {},
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


def _event(db, source, cve, payload=None, received_at=None):
    event = IngestEvent(
        source_id=source.id,
        payload=payload or {"cve_id": cve},
        raw_text=cve,
        status="done",
        extracted_cves=[cve],
    )
    if received_at is not None:
        event.received_at = received_at
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def test_local_file_event_kept_when_cves_already_known():
    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    first = ingest_payload(
        db,
        source,
        payload={"cve_id": "CVE-2024-3094", "filename": "input1.txt"},
        raw_text="CVE-2024-3094",
    )
    second = ingest_payload(
        db,
        source,
        payload={"cve_id": "CVE-2024-3094", "cves": ["CVE-2024-3094", "CVE-2022-0121"], "filename": "input2.txt"},
        raw_text="CVE-2024-3094 CVE-2022-0121",
    )
    assert first is not None
    assert second is not None
    assert second.payload["filename"] == "input2.txt"
    assert second.extracted_cves == ["CVE-2024-3094", "CVE-2022-0121"]
    assert db.query(IngestEvent).count() == 2


def test_same_local_file_reuses_one_ingest_event():
    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    first = ingest_payload(
        db,
        source,
        payload={"cve_id": "CVE-2022-0121", "cves": ["CVE-2022-0121"], "filename": "input2.txt"},
        raw_text="CVE-2022-0121",
    )
    second = ingest_payload(
        db,
        source,
        payload={
            "cve_id": "CVE-2022-0121",
            "cves": ["CVE-2022-0121", "CVE-2025-38003"],
            "filename": "input2.txt",
        },
        raw_text="CVE-2022-0121\nCVE-2025-38003",
    )
    assert first is not None
    assert second is not None
    assert first.id == second.id
    assert db.query(IngestEvent).count() == 1
    assert second.extracted_cves == ["CVE-2022-0121", "CVE-2025-38003"]
    assert second.payload["cves"] == ["CVE-2022-0121", "CVE-2025-38003"]


def test_purge_keeps_local_file_events_even_if_cve_repeats():
    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    older = _event(
        db,
        source,
        "CVE-2024-3094",
        payload={"cve_id": "CVE-2024-3094", "filename": "input1.txt"},
    )
    newer = _event(
        db,
        source,
        "CVE-2024-3094",
        payload={"cve_id": "CVE-2024-3094", "filename": "input2.txt"},
    )
    removed = purge_duplicate_ingest_events(db)
    db.commit()
    ids = {row.id for row in db.query(IngestEvent).all()}
    assert removed == 0
    assert older.id in ids
    assert newer.id in ids


def test_purge_keeps_one_event_per_local_filename():
    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    now = datetime.now(timezone.utc)
    older = _event(
        db,
        source,
        "CVE-2022-0121",
        payload={"cve_id": "CVE-2022-0121", "filename": "input2.txt"},
        received_at=now - timedelta(minutes=30),
    )
    newer = _event(
        db,
        source,
        "CVE-2025-38003",
        payload={
            "cve_id": "CVE-2022-0121",
            "cves": ["CVE-2022-0121", "CVE-2025-38003"],
            "filename": "input2.txt",
        },
        received_at=now,
    )
    newer.extracted_cves = ["CVE-2022-0121", "CVE-2025-38003"]
    db.commit()
    removed = purge_duplicate_ingest_events(db)
    db.commit()
    rows = db.query(IngestEvent).all()
    assert removed == 1
    assert {row.id for row in rows} == {newer.id}
    assert older.id not in {row.id for row in rows}


def test_ingest_payload_records_already_queued_cve_as_skipped():
    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    first = ingest_payload(db, source, payload={"cve_id": "CVE-2024-3094"})
    second = ingest_payload(db, source, payload={"cve_id": "CVE-2024-3094"})
    assert first is not None
    assert second is not None
    assert first.id != second.id
    assert second.status == "skipped"
    assert second.payload["_duplicate"] is True
    assert db.query(IngestEvent).count() == 2


def test_same_local_file_all_known_keeps_original_and_plays_duplicate():
    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    first = ingest_payload(
        db,
        source,
        payload={"cve_id": "CVE-2024-3094", "filename": "input1.txt"},
        raw_text="CVE-2024-3094",
    )
    second = ingest_payload(
        db,
        source,
        payload={"cve_id": "CVE-2024-3094", "filename": "input1.txt"},
        raw_text="CVE-2024-3094",
    )
    assert first is not None
    assert second is not None
    assert first.id != second.id
    assert first.status == "queued"
    assert first.payload.get("filename") == "input1.txt"
    assert second.status == "skipped"
    assert second.payload.get("_duplicate") is True
    assert second.payload.get("filename") in (None, "")
    assert second.payload.get("_origin_filename") == "input1.txt"


def test_purge_keeps_original_event_and_newest_duplicate_play():
    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    now = datetime.now(timezone.utc)
    original = _event(db, source, "CVE-2024-3094", received_at=now - timedelta(minutes=5))
    play = _event(
        db,
        source,
        "CVE-2024-3094",
        payload={"cve_id": "CVE-2024-3094", "_duplicate": True},
        received_at=now,
    )
    play.status = "skipped"
    db.commit()
    older_play = _event(
        db,
        source,
        "CVE-2024-3094",
        payload={"cve_id": "CVE-2024-3094", "_duplicate": True},
        received_at=now - timedelta(minutes=1),
    )
    older_play.status = "skipped"
    db.commit()
    removed = purge_duplicate_ingest_events(db)
    db.commit()
    ids = {row.id for row in db.query(IngestEvent).all()}
    assert removed == 1
    assert original.id in ids
    assert play.id in ids
    assert older_play.id not in ids


def test_atom_payload_reingests_existing_cve():
    db = _session()
    source = _source(db)
    first = ingest_payload(
        db,
        source,
        payload={
            "cve_id": "CVE-2024-3094",
            "feed_url": "https://vendor.example/atom.xml",
            "title": "old title",
        },
    )
    second = ingest_payload(
        db,
        source,
        payload={
            "cve_id": "CVE-2024-3094",
            "feed_url": "https://vendor.example/atom.xml",
            "title": "updated advisory",
            "summary": "new text",
        },
    )
    assert first is not None
    assert second is not None
    assert first.id != second.id
    assert db.query(IngestEvent).count() == 2
    assert second.payload["_refresh"] is True


def test_local_ingest_skips_cve_before_intel_start(monkeypatch):
    monkeypatch.setenv("INTEL_START_DATE", "2024-01-01")
    from app.config import get_settings

    get_settings.cache_clear()
    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    event = ingest_payload(db, source, payload={"cve_id": "CVE-2022-0121"}, raw_text="CVE-2022-0121")
    assert event is None
    get_settings.cache_clear()


def test_atom_ingest_skips_cve_before_intel_start(monkeypatch):
    monkeypatch.setenv("INTEL_START_DATE", "2024-01-01")
    from app.config import get_settings

    get_settings.cache_clear()
    db = _session()
    source = _source(db)
    event = ingest_payload(db, source, payload={"cve_id": "CVE-2022-0121"})
    assert event is None
    get_settings.cache_clear()


def test_purge_drops_atom_rows_when_no_feed_is_configured():
    db = _session()
    source = _source(db)
    leftover = _event(db, source, "CVE-1999-0082", payload={"cve_id": "CVE-1999-0082", "summary": "NVD item"})
    real = _event(
        db,
        source,
        "CVE-2024-3094",
        payload={"cve_id": "CVE-2024-3094", "feed_url": "https://vendor.example/atom.xml"},
    )
    removed = purge_unconfigured_atom_events(db)
    db.commit()
    ids = {row.id for row in db.query(IngestEvent).all()}
    assert leftover.id not in ids
    assert real.id not in ids
    assert removed >= 1


def test_purge_keeps_real_atom_entries_when_feeds_exist():
    db = _session()
    source = _source(
        db,
        config={"feeds": [{"url": "https://vendor.example/atom.xml", "name": "Vendor", "token": ""}]},
    )
    leftover = _event(db, source, "CVE-2024-1111", payload={"cve_id": "CVE-2024-1111"})
    real = _event(
        db,
        source,
        "CVE-2024-3094",
        payload={"cve_id": "CVE-2024-3094", "feed_url": "https://vendor.example/atom.xml"},
    )
    purge_unconfigured_atom_events(db)
    db.commit()
    ids = {row.id for row in db.query(IngestEvent).all()}
    assert leftover.id not in ids
    assert real.id in ids


def test_purge_duplicate_keeps_newest_row_per_cve():
    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    now = datetime.now(timezone.utc)
    older = _event(db, source, "CVE-2024-3094", received_at=now - timedelta(minutes=5))
    newer = _event(db, source, "CVE-2024-3094", received_at=now)
    removed = purge_duplicate_ingest_events(db)
    db.commit()
    ids = {row.id for row in db.query(IngestEvent).all()}
    assert removed == 1
    assert older.id not in ids
    assert newer.id in ids


def test_cleanup_deletes_legacy_nvd_source_instead_of_relabeling_as_atom():
    db = _session()
    leftover = _source(db, name="NVD API Feed", source_type="api_feed")
    event = _event(db, leftover, "CVE-1999-0082")
    atom = _source(db)
    cleanup_input_sources(db)
    db.commit()
    types = {row.source_type for row in db.query(InputSource).all()}
    assert "api_feed" not in types
    assert db.get(IngestEvent, event.id) is None
    assert db.get(InputSource, leftover.id) is None
    assert db.get(InputSource, atom.id) is not None
    assert db.query(IngestEvent).filter(IngestEvent.source_id == atom.id).count() == 0


def test_delete_events_by_id_chunks_large_lists():
    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    events = [_event(db, source, f"CVE-2024-{i:04d}") for i in range(1, 8)]
    removed = _delete_events_by_id(db, [event.id for event in events], chunk_size=2)
    db.commit()
    assert removed == 7
    assert db.query(IngestEvent).count() == 0


def test_ingest_inline_queues_cve_and_records_duplicates():
    db = _session()
    event = ingest_inline_cve(db, cve_id="CVE-2024-3094")
    assert event is not None
    assert event.extracted_cves == ["CVE-2024-3094"]
    assert event.payload["origin"] == "inline"
    source = db.get(InputSource, event.source_id)
    assert source.source_type == "inline"
    assert source.enabled is True
    again = ingest_inline_cve(db, cve_id="CVE-2024-3094")
    assert again.status == "skipped"
    assert again.payload["_duplicate"] is True
    assert again.id != event.id


def test_ingest_inline_reads_cve_from_advisory_text():
    db = _session()
    event = ingest_inline_cve(db, sample_text="Vendor advisory mentions CVE-2025-1111.")
    assert event.extracted_cves == ["CVE-2025-1111"]


def test_ingest_inline_rejects_empty_input():
    db = _session()
    try:
        ingest_inline_cve(db, cve_id="not-a-cve")
        raise AssertionError("expected invalid inline ingest to fail")
    except InlineIngestError as exc:
        assert exc.status_code == 400


def test_queue_cve_rerun_queues_known_cve():
    from app.models.vulnerability import Vulnerability

    db = _session()
    db.add(Vulnerability(cve_id="CVE-2023-46805", title="ics", pipeline_status="completed"))
    db.commit()
    event = queue_cve_rerun(db, "CVE-2023-46805")
    assert event.status == "queued"
    assert event.extracted_cves == ["CVE-2023-46805"]
    assert event.payload["_rerun"] is True
    assert event.payload["_refresh"] is True
    assert event.payload["origin"] == "inline"


def test_queue_cve_rerun_rejects_unknown_cve():
    db = _session()
    try:
        queue_cve_rerun(db, "CVE-2023-46805")
        raise AssertionError("expected missing CVE to fail")
    except InlineIngestError as exc:
        assert exc.status_code == 404


def test_done_ingest_event_is_not_known_without_vulnerability():
    from app.services.ingestion import _known_cve_ids, skip_unchanged_ingest_file

    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    event = ingest_payload(
        db,
        source,
        payload={"cve_id": "CVE-2024-3094", "filename": "inbox.txt"},
        raw_text="CVE-2024-3094",
    )
    event.status = "done"
    db.commit()
    assert "CVE-2024-3094" not in _known_cve_ids(db, ["CVE-2024-3094"])
    assert skip_unchanged_ingest_file(db, source.id, "inbox.txt", "10:1", "10:1") is False


def test_unchanged_file_skipped_while_cve_queued_or_stored():
    from app.models.vulnerability import Vulnerability
    from app.services.ingestion import skip_unchanged_ingest_file

    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    ingest_payload(
        db,
        source,
        payload={"cve_id": "CVE-2024-3094", "filename": "inbox.txt"},
        raw_text="CVE-2024-3094",
    )
    assert skip_unchanged_ingest_file(db, source.id, "inbox.txt", "10:1", "10:1") is True
    assert skip_unchanged_ingest_file(db, source.id, "inbox.txt", "10:1", "11:2") is False

    event = db.query(IngestEvent).one()
    event.status = "done"
    db.add(Vulnerability(cve_id="CVE-2024-3094", title="kept"))
    db.commit()
    assert skip_unchanged_ingest_file(db, source.id, "inbox.txt", "10:1", "10:1") is True

    db.query(Vulnerability).delete()
    db.commit()
    assert skip_unchanged_ingest_file(db, source.id, "inbox.txt", "10:1", "10:1") is False


def test_pull_local_rereads_file_after_cve_deleted(tmp_path):
    from app.api.settings.feeds import pull_local_files
    from app.models.vulnerability import Vulnerability

    folder = tmp_path / "inbox"
    folder.mkdir()
    (folder / "inbox.txt").write_text("CVE-2024-3094\n", encoding="utf-8")
    db = _session()
    source = _source(db, name="Local folder", source_type="local", config={"path": str(folder)})
    first = pull_local_files(db, source)
    assert first == 1
    db.add(Vulnerability(cve_id="CVE-2024-3094", title="kept"))
    db.commit()
    assert pull_local_files(db, source) == 0
    db.query(Vulnerability).delete()
    db.query(IngestEvent).update({"status": "done"})
    db.commit()
    assert pull_local_files(db, source) == 1


def test_cleanup_keeps_inline_source():
    db = _session()
    inline = _source(db, name="Inline CVE", source_type="inline")
    cleanup_input_sources(db)
    db.commit()
    assert db.get(InputSource, inline.id) is not None
    assert {row.source_type for row in db.query(InputSource).all()} == {"inline"}
